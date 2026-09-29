#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "icmp.h"
#include "netlink.h"
#include "sockaddr_util.h"

static int fd, mtu_size;
static union sockaddr_any to;

static void usage(void)
{
	fprintf(stderr,
		"usage: mtu [-4|-6] -i <mtu-size> <host>\n"
		"       mtu [-4|-6] -I <host>\n"
		"       mtu [-4|-6] -d <host>\n"
		"       mtu [-4|-6] -D <host>\n"
		"\n"
		" -4              Use IPv4\n"
		" -6              Use IPv6 (link-local hosts need %%interface)\n"
		" -i <mtu-size>   Inject <mtu-size> as PMTU to <host>\n"
		" -I              Inject local PMTU as PMTU to <host>\n"
		" -d              Discover PMTU (up to 9000 bytes for IPv6, 1500 for IPv4)\n"
		" -D              Discover PMTU to <host> and assign it to interface MTU\n");
	exit(3);
}

static void print_reply(union sockaddr_any *from, struct icmp_reply *reply)
{
	char address[80];
	const char *message = NULL;

	printf("From %s: icmp_seq=%u ",
	       sockaddr_to_string(from, address, sizeof(address)), reply->seq);
	if (reply->echo_reply) {
		printf("bytes=%d\n", reply->bytes);
		return;
	}
	if (from->sa.sa_family == AF_INET6) {
		switch (reply->type) {
		case ICMP6_PACKET_TOO_BIG:
			printf("Packet too big (mtu = %u)\n", reply->mtu);
			return;
		case ICMP6_DST_UNREACH:
			switch (reply->code) {
			case ICMP6_DST_UNREACH_NOROUTE: message = "No route to destination"; break;
			case ICMP6_DST_UNREACH_ADMIN: message = "Communication administratively prohibited"; break;
			case ICMP6_DST_UNREACH_BEYONDSCOPE: message = "Beyond scope of source address"; break;
			case ICMP6_DST_UNREACH_ADDR: message = "Address unreachable"; break;
			case ICMP6_DST_UNREACH_NOPORT: message = "Destination Port Unreachable"; break;
			}
			break;
		case ICMP6_TIME_EXCEEDED:
			message = reply->code == ICMP6_TIME_EXCEED_TRANSIT ?
				"Hop limit exceeded" : "Frag reassembly time exceeded";
			break;
		case ICMP6_PARAM_PROB:
			printf("Parameter problem: pointer = %u\n", reply->info);
			return;
		}
	} else {
		switch (reply->type) {
		case ICMP_DEST_UNREACH:
			switch (reply->code) {
			case ICMP_NET_UNREACH: message = "Destination Net Unreachable"; break;
			case ICMP_HOST_UNREACH: message = "Destination Host Unreachable"; break;
			case ICMP_PROT_UNREACH: message = "Destination Protocol Unreachable"; break;
			case ICMP_PORT_UNREACH: message = "Destination Port Unreachable"; break;
			case ICMP_SR_FAILED: message = "Source Route Failed"; break;
			case ICMP_PKT_FILTERED: message = "Packet filtered"; break;
			case ICMP_FRAG_NEEDED:
				printf("Frag needed and DF set (mtu = %u)\n", reply->mtu);
				return;
			}
			break;
		case ICMP_TIME_EXCEEDED:
			message = reply->code == ICMP_EXC_TTL ?
				"Time to live exceeded" : "Frag reassembly time exceeded";
			break;
		case ICMP_PARAMETERPROB:
			printf("Parameter problem: pointer = %u\n", reply->info >> 24);
			return;
		}
	}
	if (message)
		printf("%s\n", message);
	else
		printf("ICMP error: type=%d code=%d\n", reply->type, reply->code);
}

static int do_ping(int seq, int size)
{
	__u8 buf[ICMP_MAX_PACKET_SIZE];
	union sockaddr_any from;
	struct icmp_reply reply;
	int len, retry;

	for (retry = 0; retry < 3; retry++) {
		if (icmp_send_ping(fd, &to.sa, sockaddr_len(&to), seq, size, NULL) < 0) {
			if (errno != EMSGSIZE)
				perror("mtu: send ping");
			return -1;
		}
		for (;;) {
			len = icmp_read_reply(fd, &from.sa, sizeof(from), buf, sizeof(buf), NULL);
			if (len <= 0)
				break;
			if (icmp_parse_reply(buf, len, seq, &from.sa, &to.sa, &reply))
				continue;
			print_reply(&from, &reply);
			if (reply.echo_reply)
				return 0;
			if (reply.mtu && reply.mtu <= ICMP_MAX_PACKET_SIZE)
				return reply.mtu;
			return -1;
		}
	}
	return -1;
}

static int discover_mtu(void)
{
	int seq = 1, low, high, size, r;

	low = to.sa.sa_family == AF_INET6 ? 1280 : 68;
	high = to.sa.sa_family == AF_INET6 ? ICMP_MAX_PACKET_SIZE : 1500;
	/* Establish a known working lower bound before binary search. */
	if (do_ping(seq++, low) != 0)
		return -1;
	while (low < high) {
		size = low + (high - low + 1) / 2;
		r = do_ping(seq++, size);
		if (r == 0)
			low = size;
		else if (r >= low && r < size)
			high = r;
		else
			high = size - 1;
	}
	return low;
}

static int do_discover(void)
{
	int mtu = discover_mtu();
	if (mtu < 0) {
		fprintf(stderr, "Failed to determine MTU: host did not reply\n");
		return 1;
	}
	printf("%d\n", mtu);
	return 0;
}

static int set_mtu(const char *dev, int mtu)
{
	struct ifreq ifr;
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	int r;

	if (sock < 0)
		return -1;
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev);
	ifr.ifr_mtu = mtu;
	r = ioctl(sock, SIOCSIFMTU, &ifr);
	if (r < 0)
		perror("SIOCSIFMTU");
	close(sock);
	return r;
}

static int do_discover_and_write(void)
{
	int mtu = discover_mtu();
	char iface[IFNAMSIZ];

	if (mtu < 0) {
		fprintf(stderr, "Failed to determine MTU\n");
		return 1;
	}
	if (!netlink_route_get(&to.sa, NULL, iface)) {
		fprintf(stderr, "Failed to determine route interface\n");
		return 1;
	}
	printf("Writing %d to %s\n", mtu, iface);
	return set_mtu(iface, mtu) < 0;
}

static int do_inject(void)
{
	__u8 buf[2048];
	union sockaddr_any from, local;
	struct icmp_reply reply;
	char address[80];
	int len, i, seq = 1, injected = 0;
	int advertised = mtu_size - 2;

	if (to.sa.sa_family == AF_INET6 && advertised < 1280)
		advertised = 1280;
	if (icmp_send_ping(fd, &to.sa, sockaddr_len(&to), seq, mtu_size, NULL) < 0) {
		perror("mtu: send ping");
		return 1;
	}
	for (i = 0; i < 5; i++) {
		len = icmp_read_reply(fd, &from.sa, sizeof(from), buf, sizeof(buf), &local.sa);
		if (len <= 0)
			continue;
		if (icmp_parse_reply(buf, len, seq, &from.sa, &to.sa, &reply))
			continue;
		print_reply(&from, &reply);
		if (!reply.echo_reply)
			continue;
		if (seq != 1)
			sleep(1);
		if (icmp_send_ping(fd, &to.sa, sockaddr_len(&to), ++seq, mtu_size, NULL) < 0)
			return 1;
		if (icmp_send_frag_needed(fd, &to.sa, sockaddr_len(&to), buf, len,
					 &local.sa, advertised) < 0) {
			perror("mtu: inject PMTU");
			return 1;
		}
		printf("To %s: %s mtu=%d\n",
		       sockaddr_to_string(&to, address, sizeof(address)),
		       to.sa.sa_family == AF_INET6 ? "packet_too_big" : "frag_needed", advertised);
		injected = 1;
	}
	return !injected;
}

static int do_inject_pmtu(void)
{
	uint32_t mtu;
	if (!netlink_route_get(&to.sa, &mtu, NULL)) {
		fprintf(stderr, "Failed to determine Path MTU\n");
		return 1;
	}
	if (mtu >= 1500)
		return 0;
	mtu_size = mtu;
	return do_inject();
}

int main(int argc, char **argv)
{
	struct addrinfo hints = { 0 }, *ai, *rp;
	int (*action)(void) = NULL;
	int opt, r;

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_RAW;
	while ((opt = getopt(argc, argv, "46DdIi:")) != -1) {
		switch (opt) {
		case '4': hints.ai_family = AF_INET; break;
		case '6': hints.ai_family = AF_INET6; break;
		case 'D': action = do_discover_and_write; break;
		case 'd': action = do_discover; break;
		case 'i': {
			char *end;
			long value = strtol(optarg, &end, 10);
			if (!*optarg || *end || value < 68 || value > 1500)
				usage();
			action = do_inject;
			mtu_size = value;
			break;
		}
		case 'I': action = do_inject_pmtu; break;
		default: usage();
		}
	}
	if (!action || optind != argc - 1)
		usage();
	r = getaddrinfo(argv[optind], NULL, &hints, &ai);
	if (r != 0) {
		fprintf(stderr, "mtu: %s: %s\n", argv[optind], gai_strerror(r));
		return 2;
	}
	for (rp = ai; rp; rp = rp->ai_next) {
		union sockaddr_any candidate;
		if (!sockaddr_from_addrinfo(&candidate, rp))
			continue;
		if (!to.sa.sa_family)
			to = candidate;
		if (netlink_route_get(&candidate.sa, NULL, NULL)) {
			to = candidate;
			break;
		}
	}
	freeaddrinfo(ai);
	if (!to.sa.sa_family)
		return 2;
	if (to.sa.sa_family == AF_INET6) {
		if (IN6_IS_ADDR_LINKLOCAL(&to.sin6.sin6_addr) && !to.sin6.sin6_scope_id) {
			fprintf(stderr, "mtu: link-local IPv6 targets require %%interface\n");
			return 2;
		}
		if (action == do_inject && mtu_size < 1280) {
			fprintf(stderr, "mtu: IPv6 MTU must be at least 1280\n");
			return 2;
		}
	}
	fd = icmp_open(to.sa.sa_family, 1.0);
	if (fd < 0)
		return 1;
	r = action();
	icmp_close(fd);
	return r;
}
