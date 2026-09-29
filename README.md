pingu
=====

Pingu is a daemon that takes care of policy routing and fail-over in
multi ISP setups.

Features
--------
- IPv4 and IPv6 monitoring, policy routing, failover and load balancing
- Support for DHCP
- Support for PPP
- ISP failover
- Load-balancing (nexthop)
- Optional route rule based on fwmark
- run script when ISP goes up/down


Build requirements
------------------
- libev 3 or newer (http://software.schmorp.de/pkg/libev.html)
- asciidoc (optional for creating man pages)

To build pingu without man pages run configure --disable-doc

IPv6
----
Hosts and interface `ping` entries accept IPv4 addresses, IPv6 addresses and
DNS names. DNS lookups try both address families by default. Use `family inet`
or `family inet6` globally or inside a host section to restrict DNS lookups;
`family any` restores the default.

```
interface eth0 {
	ping 2001:db8::1
	ping fe80::1
}
host example.net {
	bind-interface eth0
	family inet6
}
```

Link-local targets use the bound interface as their scope. Without
`bind-interface`, specify a zone, such as `fe80::1%eth0`.
IPv4 and IPv6 have separate sockets, primary addresses, source/fwmark rules
and multipath routes. IPv6 prefers a stable global address over a link-local
address; tentative, failed-DAD and temporary addresses are not selected.
Gateway health remains an interface-wide decision: `required-hosts-online`
counts all configured hosts, and a gateway transition affects both families.

The `mtu` utility supports both families in all four modes:

```
mtu -6 -d 2001:db8::1       # discover path MTU
mtu -6 -d fe80::1%eth0     # link-local destination
mtu -4 -d 192.0.2.1        # force IPv4
mtu -6 -D 2001:db8::1      # discover and set the outgoing interface MTU
mtu -6 -i 1400 2001:db8::1 # inject a Packet Too Big message
mtu -6 -I 2001:db8::1      # inject using the current path MTU
```

Omit `-4`/`-6` to resolve either family. Raw ICMP sockets require root or
`CAP_NET_RAW`; changing an interface MTU also requires `CAP_NET_ADMIN`.
IPv6 discovery supports path MTUs from 1280 through 9000 bytes, including
jumbo frames. IPv4 discovery retains the 1500-byte upper limit.
Probe replies and ICMP errors are printed before the final discovered MTU.
Injection retains the existing two-byte reduction from the probe size,
clamped to 1280 for IPv6.

Tests
-----
Run `make check` for packet parsing, address and interface-state tests.
Run `make check-integration` for live IPv4/IPv6 probing, PMTU discovery and
injection, policy rules, failover and load balancing. Integration tests need
Python 3, iproute2, util-linux, and support for unprivileged user/network
namespaces. All network changes stay inside disposable namespaces.
