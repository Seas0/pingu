#!/usr/bin/env python3
"""Live tests in disposable user/network namespaces; never change host routes."""
import contextlib
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def run(*args, peer=None, check=True, timeout=15):
    cmd = [str(a) for a in args]
    if peer:
        cmd = ['nsenter', '-t', str(peer.pid), '-n', *cmd]
    result = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise AssertionError(f'{cmd}: {result.returncode}\n{result.stdout}{result.stderr}')
    return result.stdout.strip()


def ip(*args, **kwargs):
    return run('ip', *args, **kwargs)


def wait_for(predicate, description, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError(f'Timed out: {description}')


@contextlib.contextmanager
def namespace():
    proc = subprocess.Popen(['unshare', '--net', 'sleep', '120'])
    try:
        wait_for(lambda: os.readlink(f'/proc/{proc.pid}/ns/net') != os.readlink('/proc/self/ns/net'),
                 'peer namespace')
        ip('link', 'set', 'lo', 'up', peer=proc)
        yield proc
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def link(peer, name, subnet):
    ip('link', 'add', name, 'type', 'veth', 'peer', 'name', f'{name}p')
    ip('link', 'set', f'{name}p', 'netns', peer.pid)
    for dev, last, ns in [(name, 1, None), (f'{name}p', 2, peer)]:
        ip('link', 'set', dev, 'up', peer=ns)
        ip('address', 'add', f'192.0.{subnet}.{last}/24', 'dev', dev, peer=ns)
        ip('-6', 'address', 'add', f'2001:db8:{subnet}::{last}/64', 'dev', dev, 'nodad', peer=ns)
        ip('-6', 'address', 'add', f'fe80::{subnet}:{last}/64', 'dev', dev, 'nodad', peer=ns)


@contextlib.contextmanager
def daemon(config):
    with tempfile.TemporaryDirectory(prefix='pingu-test-') as temp:
        tmp = Path(temp)
        (tmp / 'pingu.conf').write_text(config)
        with (tmp / 'log').open('w+') as log:
            proc = subprocess.Popen([str(ROOT / 'src/pingu'), '-v', '-c', str(tmp / 'pingu.conf'),
                                     '-p', str(tmp / 'pid'), '-a', str(tmp / 'socket')],
                                    stdout=log, stderr=log)
            try:
                wait_for(lambda: (tmp / 'socket').exists() or proc.poll() is not None, 'daemon startup')
                assert proc.poll() is None, 'daemon exited at startup'
                yield tmp
            except BaseException:
                print('\n'.join((tmp / 'log').read_text().splitlines()[-80:]), file=sys.stderr)
                raise
            finally:
                if proc.poll() is None:
                    proc.send_signal(signal.SIGINT)
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
                        raise AssertionError('daemon did not shut down')
                assert proc.returncode == 0, f'daemon exited {proc.returncode}'


def status(tmp):
    return run(ROOT / 'src/pinguctl', '-a', tmp / 'socket', 'host-status')


def main():
    ip('link', 'set', 'lo', 'up')
    mtu = ROOT / 'src/mtu'
    for family, target in [('-4', '127.0.0.1'), ('-6', '::1')]:
        output = run(mtu, family, '-d', target)
        assert output.splitlines()[-1] == ('9000' if family == '-6' else '1500')
        assert f'From {target}: icmp_seq=1 bytes=' in output
        assert run(mtu, family, '-I', target) == ''  # link MTU fallback (65536)
    print('PASS: IPv4/IPv6 loopback discovery and route MTU lookup', flush=True)
    with daemon('''interval 0.3
retry 1
required 1
timeout 0.1
host localhost {
 family inet6
 label loop6
}
host localhost {
 family inet
 label loop4
}
''') as tmp:
        wait_for(lambda: all(f'{label}: got seq' in (tmp / 'log').read_text()
                             for label in ['loop4', 'loop6']), 'family-specific DNS probes')
    print('PASS: daemon IPv4/IPv6 DNS selection and unbound probes', flush=True)
    with namespace() as peer, namespace() as peer2:
        link(peer, 'wan0', 2)
        link(peer2, 'wan1', 3)
        for size in [9000, 8501]:
            ip('link', 'set', 'wan1', 'mtu', size)
            ip('link', 'set', 'wan1p', 'mtu', size, peer=peer2)
            for target in ['2001:db8:3::2', 'fe80::3:2%wan1']:
                output = run(mtu, '-6', '-d', target)
                assert output.splitlines()[-1] == str(size), output
                assert f'bytes={size - 40}' in output, output
        ip('link', 'set', 'wan1', 'mtu', 1500)
        ip('link', 'set', 'wan1p', 'mtu', 1500, peer=peer2)
        print('PASS: IPv6 9000/8501-byte discovery with global and scoped targets', flush=True)
        # A reduced outgoing link exercises EMSGSIZE and byte-exact discovery.
        ip('link', 'set', 'wan0', 'mtu', 1401)
        ip('link', 'set', 'wan0p', 'mtu', 1401, peer=peer)
        for family, target in [('-4', '192.0.2.2'), ('-6', '2001:db8:2::2'), ('-6', 'fe80::2:2%wan0')]:
            output = run(mtu, family, '-d', target)
            assert output.splitlines()[-1] == '1401', output
            assert 'icmp_seq=1 bytes=' in output
        print('PASS: reduced MTU discovery and scoped IPv6 target', flush=True)
        assert 'To 2001:db8:2::2: packet_too_big mtu=1398' in run(mtu, '-6', '-i', '1400', '2001:db8:2::2')
        assert 'mtu 1398' in ip('-6', 'route', 'get', '2001:db8:2::1', peer=peer)
        print('PASS: IPv6 Packet Too Big injection updates peer PMTU', flush=True)
        ip('link', 'set', 'wan0', 'mtu', 1500)
        ip('link', 'set', 'wan0p', 'mtu', 1500, peer=peer)
        # Route through a router with a narrower downstream link, so the
        # utility must decode real ICMP errors rather than local EMSGSIZE.
        ip('link', 'add', 'transit0', 'type', 'veth', 'peer', 'name', 'transit1')
        ip('link', 'set', 'transit0', 'netns', peer.pid)
        ip('link', 'set', 'transit1', 'netns', peer2.pid)
        for ns, dev, last in [(peer, 'transit0', 1), (peer2, 'transit1', 2)]:
            ip('link', 'set', dev, 'up', 'mtu', '1380', peer=ns)
            ip('addr', 'add', f'198.51.100.{last}/24', 'dev', dev, peer=ns)
            ip('-6', 'addr', 'add', f'2001:db8:5::{last}/64', 'dev', dev, 'nodad', peer=ns)
        run('sysctl', '-qw', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1', peer=peer)
        ip('route', 'add', '198.51.100.0/24', 'via', '192.0.2.2', 'dev', 'wan0')
        ip('-6', 'route', 'add', '2001:db8:5::/64', 'via', '2001:db8:2::2', 'dev', 'wan0')
        ip('route', 'add', '192.0.2.0/24', 'via', '198.51.100.1', 'dev', 'transit1', peer=peer2)
        ip('-6', 'route', 'add', '2001:db8:2::/64', 'via', '2001:db8:5::1', 'dev', 'transit1', peer=peer2)
        for family, target, diagnostic in [('-4', '198.51.100.2', 'Frag needed and DF set'),
                                           ('-6', '2001:db8:5::2', 'Packet too big')]:
            output = run(mtu, family, '-d', target)
            assert output.splitlines()[-1] == '1380', output
            assert f'{diagnostic} (mtu = 1380)' in output, output
        output = run(mtu, '-6', '-I', '2001:db8:5::2')
        assert 'packet_too_big mtu=1378' in output, output
        output = run(mtu, '-6', '-D', '2001:db8:5::2')
        assert 'Writing 1380 to wan0' in output, output
        assert 'mtu 1380' in ip('link', 'show', 'wan0')
        ip('link', 'set', 'wan0', 'mtu', 1500)
        output = run(mtu, '-4', '-i', '1400', '192.0.3.2')
        assert 'frag_needed mtu=1398' in output, output
        print('PASS: routed PMTU errors and diagnostics, IPv6 -D/-I, IPv4 injection', flush=True)
        # Jumbo upstream links with a smaller jumbo bottleneck exercise a
        # Packet Too Big MTU above 1500, plus the shared -D discovery path.
        ip('link', 'set', 'wan0', 'mtu', 9000)
        ip('link', 'set', 'wan0p', 'mtu', 9000, peer=peer)
        ip('link', 'set', 'transit0', 'mtu', 6001, peer=peer)
        ip('link', 'set', 'transit1', 'mtu', 6001, peer=peer2)
        output = run(mtu, '-6', '-d', '2001:db8:5::2')
        assert output.splitlines()[-1] == '6001', output
        assert 'Packet too big (mtu = 6001)' in output, output
        output = run(mtu, '-6', '-D', '2001:db8:5::2')
        assert 'Writing 6001 to wan0' in output, output
        assert 'mtu 6001' in ip('link', 'show', 'wan0')
        ip('link', 'set', 'wan0', 'mtu', 1500)
        ip('link', 'set', 'wan0p', 'mtu', 1500, peer=peer)
        print('PASS: routed jumbo PMTU error and interface MTU assignment', flush=True)
        for family, gw in [('-4', '192.0.2.2'), ('-6', 'fe80::2:2')]:
            ip(family, 'route', 'add', 'default', 'via', gw, 'dev', 'wan0', 'metric', '100')
        config = '''interval 0.3
retry 1
required 1
timeout 0.1
interface wan0 {
 route-table 100
 rule-priority 10000
 fwmark 42
 ping 192.0.2.2
 ping 2001:db8:2::2
 ping fe80::2:2
}
'''
        with daemon(config) as tmp:
            wait_for(lambda: all(f'{host}: got seq' in (tmp / 'log').read_text() for host in
                                ['192.0.2.2', '2001:db8:2::2', 'fe80::2:2']), 'echo replies for each family and scope')
            wait_for(lambda: all(f'{host}: 1' in status(tmp) for host in
                                ['192.0.2.2', '2001:db8:2::2', 'fe80::2:2']), 'mixed probes')
            for family, source in [('-4', '192.0.2.1'), ('-6', '2001:db8:2::1')]:
                rules = ip(family, 'rule', 'show')
                assert f'from {source} lookup 100' in rules, rules
                assert 'fwmark 0x2a lookup 100' in rules, rules
                assert 'default via' in ip(family, 'route', 'show', 'table', '100')
            # Removing IPv6 must retain IPv4 policy rules and route mirroring.
            ip('-6', 'address', 'add', '2001:db8:2::10/64', 'dev', 'wan0', 'nodad')
            ip('-6', 'address', 'del', '2001:db8:2::1/64', 'dev', 'wan0')
            wait_for(lambda: 'from 2001:db8:2::10 lookup 100' in ip('-6', 'rule'), 'IPv6 primary replacement')
            assert 'from 2001:db8:2::1 lookup 100' not in ip('-6', 'rule')
            assert 'from 192.0.2.1 lookup 100' in ip('-4', 'rule')
            assert 'default via' in ip('-4', 'route', 'show', 'table', '100')
            # Losing all configured probe hosts removes both main-table defaults.
            run('sysctl', '-qw', 'net.ipv6.conf.wan0p.keep_addr_on_down=1', peer=peer)
            ip('link', 'set', 'wan0p', 'down', peer=peer)
            wait_for(lambda: all(f'{host}: 0' in status(tmp) for host in
                                ['192.0.2.2', '2001:db8:2::2', 'fe80::2:2']), 'offline probes')
            assert not ip('-4', 'route', 'show', 'default')
            assert not ip('-6', 'route', 'show', 'default')
            ip('link', 'set', 'wan0p', 'up', peer=peer)
            wait_for(lambda: '2001:db8:2::2: 1' in status(tmp), 'IPv6 recovery')
            wait_for(lambda: 'default via' in ip('-6', 'route', 'show', 'default'), 'default route recovery')
        for family in ['-4', '-6']:
            assert 'lookup 100' not in ip(family, 'rule')
            assert not ip(family, 'route', 'show', 'table', '100', check=False)
        print('PASS: dual-stack probes, policy routing, address replacement, failover and cleanup', flush=True)
        # Multipath construction must never mix gateways from different families.
        for family, gw in [('-4', '192.0.3.2'), ('-6', 'fe80::3:2')]:
            ip(family, 'route', 'add', 'default', 'via', gw, 'dev', 'wan1', 'metric', '200')
        with daemon('''interface wan0 {
 route-table 100
 load-balance
}
interface wan1 {
 route-table 101
 load-balance
}
''') as tmp:
            for family, gateways in [('-4', ['192.0.2.2', '192.0.3.2']), ('-6', ['fe80::2:2', 'fe80::3:2'])]:
                wait_for(lambda f=family: ip(f, 'route', 'show', 'default').count('nexthop') == 2,
                         f'{family} multipath')
                routes = ip(family, 'route', 'show', 'default')
                assert all(f'nexthop via {gw}' in routes for gw in gateways), routes
        assert 'nexthop' not in ip('-6', 'route', 'show', 'default')
        print('PASS: separate IPv4/IPv6 multipath routes and cleanup', flush=True)


if __name__ == '__main__':
    if '--inside' not in sys.argv:
        sys.exit(subprocess.call(['unshare', '--user', '--map-root-user', '--net',
                                  sys.executable, __file__, '--inside']))
    main()
