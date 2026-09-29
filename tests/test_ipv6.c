#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>

#include "icmp.h"
#include "pingu_iface.h"
#include "pingu_route.h"
#include "sockaddr_util.h"

static unsigned char sent[ICMP_MAX_PACKET_SIZE];
static size_t sent_len;
static struct in6_pktinfo sent_info;

/* Exercise identifiers with a PID beyond the 16-bit ICMP identifier range. */
pid_t __wrap_getpid(void)
{
	return 0x123456;
}

ssize_t __wrap_sendto(int fd, const void *buf, size_t len, int flags,
		      const struct sockaddr *to, socklen_t tolen)
{
	assert(len <= sizeof(sent));
	assert(tolen == (to->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in)));
	memcpy(sent, buf, len);
	sent_len = len;
	return len;
}

ssize_t __wrap_sendmsg(int fd, const struct msghdr *msg, int flags)
{
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);
	assert(cmsg && cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO);
	memcpy(&sent_info, CMSG_DATA(cmsg), sizeof(sent_info));
	return __wrap_sendto(fd, msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len,
			     flags, msg->msg_name, msg->msg_namelen);
}

static uint16_t checksum(const void *data, int len)
{
	const unsigned char *p = data;
	unsigned int sum = 0;
	for (int i = 0; i < len; i++)
		sum += p[i] << (i % 2 ? 0 : 8);
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return htons(~sum);
}

static union sockaddr_any address(int family, const char *text)
{
	union sockaddr_any addr;
	sockaddr_init(&addr, family, NULL);
	assert(inet_pton(family, text, family == AF_INET6 ?
		       (void *)&addr.sin6.sin6_addr : (void *)&addr.sin.sin_addr) == 1);
	return addr;
}

static void test_addresses(void)
{
	union sockaddr_any a = address(AF_INET6, "fe80::1"), b, zero;
	struct addrinfo ai = { .ai_family = AF_INET6, .ai_addr = &a.sa, .ai_addrlen = sizeof(a.sin6) };
	char text[80];
	a.sin6.sin6_scope_id = 7;
	assert(sockaddr_from_addrinfo(&b, &ai) == &b);
	assert(sockaddr_cmp(&a, &b) == 0);
	assert(!strcmp(sockaddr_to_string(&b, text, sizeof(text)), "fe80::1%7"));
	b.sin6.sin6_scope_id = 8;
	assert(sockaddr_cmp(&a, &b) != 0);
	assert(sockaddr_from_addrinfo(&zero, NULL) == &zero);
	assert(zero.sa.sa_family == AF_UNSPEC);
	assert(!strcmp(sockaddr_to_string(&zero, text, sizeof(text)), ""));
	assert(sockaddr_init(&a, AF_INET6, NULL) && a.sa.sa_family == AF_INET6);
	assert(IN6_IS_ADDR_UNSPECIFIED(&a.sin6.sin6_addr));
}

static void test_echo(int family, int size)
{
	union sockaddr_any target = address(family, family == AF_INET6 ? "2001:db8::2" : "192.0.2.2");
	union sockaddr_any source = address(family, family == AF_INET6 ? "2001:db8::1" : "192.0.2.1");
	unsigned char packet[ICMP_MAX_PACKET_SIZE] = { 0 };
	struct icmp_reply reply;
	struct icmp6_hdr echo;
	int offset = family == AF_INET6 ? 0 : sizeof(struct iphdr);
	int len;

	assert(icmp_send_ping(0, &target.sa, sockaddr_len(&target), 42,
			      ICMP_MAX_PACKET_SIZE + 1, NULL) == -1);
	assert(errno == EMSGSIZE);
	if (family == AF_INET6)
		source.sin6.sin6_scope_id = 7;
	assert(icmp_send_ping(0, &target.sa, sockaddr_len(&target), 42, size, &source.sa) == 0);
	memcpy(&echo, sent, sizeof(echo));
	assert(echo.icmp6_type == (family == AF_INET6 ? ICMP6_ECHO_REQUEST : ICMP_ECHO));
	assert(ntohs(echo.icmp6_id) == 0x3456 && ntohs(echo.icmp6_seq) == 42);
	assert(sent_len == size - (family == AF_INET6 ? 40 : 20));
	if (family == AF_INET6) {
		assert(echo.icmp6_cksum == 0);
		assert(sent_info.ipi6_ifindex == 7);
		assert(IN6_ARE_ADDR_EQUAL(&sent_info.ipi6_addr, &source.sin6.sin6_addr));
	} else {
		struct iphdr ip = { .version = 4, .ihl = 5, .protocol = IPPROTO_ICMP };
		memcpy(packet, &ip, sizeof(ip));
		assert(checksum(sent, sent_len) == 0);
	}
	memcpy(packet + offset, sent, sent_len);
	packet[offset] = family == AF_INET6 ? ICMP6_ECHO_REPLY : ICMP_ECHOREPLY;
	packet[offset + 2] = packet[offset + 3] = 0;
	if (family == AF_INET) {
		uint16_t sum = checksum(packet + offset, sent_len);
		memcpy(packet + offset + 2, &sum, sizeof(sum));
	}
	len = offset + sent_len;
	assert(icmp_parse_reply(packet, len, 42, &target.sa, &target.sa, &reply) == 0);
	assert(reply.echo_reply && reply.seq == 42 && reply.bytes == sent_len);
	assert(icmp_parse_reply(packet, len, 43, &target.sa, &target.sa, &reply) != 0);
	assert(icmp_parse_reply(packet, len, 42, &source.sa, &target.sa, &reply) != 0);
	for (int n = 0; n < offset + 8; n++)
		assert(icmp_parse_reply(packet, n, 42, &target.sa, &target.sa, &reply) != 0);
	assert(icmp_send_frag_needed(0, &target.sa, sockaddr_len(&target), packet, len,
				    &source.sa, family == AF_INET6 ? 1280 : 68) == 0);
	memcpy(&echo, sent, sizeof(echo));
	if (family == AF_INET6) {
		struct ip6_hdr quote;
		assert(echo.icmp6_type == ICMP6_PACKET_TOO_BIG && ntohl(echo.icmp6_mtu) == 1280);
		assert(sent_len <= 1240);
		memcpy(&quote, sent + 8, sizeof(quote));
		assert(IN6_ARE_ADDR_EQUAL(&quote.ip6_src, &target.sin6.sin6_addr));
		assert(IN6_ARE_ADDR_EQUAL(&quote.ip6_dst, &source.sin6.sin6_addr));
	} else {
		assert(echo.icmp6_type == ICMP_DEST_UNREACH && echo.icmp6_code == ICMP_FRAG_NEEDED);
		assert(ntohs(echo.icmp6_data16[1]) == 68 && checksum(sent, sent_len) == 0);
	}
}

static void test_packet_too_big(void)
{
	union sockaddr_any target = address(AF_INET6, "2001:db8::2");
	union sockaddr_any router = address(AF_INET6, "fe80::1");
	unsigned char packet[64] = { 0 };
	struct icmp6_hdr error = { .icmp6_type = ICMP6_PACKET_TOO_BIG };
	struct ip6_hdr ip = { 0 };
	struct icmp6_hdr echo = { .icmp6_type = ICMP6_ECHO_REQUEST };
	struct icmp_reply reply;

	error.icmp6_mtu = htonl(6001);
	ip.ip6_vfc = 0x60;
	ip.ip6_nxt = IPPROTO_HOPOPTS;
	ip.ip6_dst = target.sin6.sin6_addr;
	echo.icmp6_id = htons((uint16_t)getpid());
	echo.icmp6_seq = htons(42);
	memcpy(packet, &error, 8);
	memcpy(packet + 8, &ip, 40);
	packet[48] = IPPROTO_ICMPV6;  /* Eight-byte hop-by-hop extension. */
	memcpy(packet + 56, &echo, 8);
	assert(!icmp_parse_reply(packet, sizeof(packet), 42, &router.sa, &target.sa, &reply));
	assert(!reply.echo_reply && reply.mtu == 6001);
	for (int n = 0; n < sizeof(packet); n++)
		assert(icmp_parse_reply(packet, n, 42, &router.sa, &target.sa, &reply));
	packet[49] = 255; /* Truncated extension. */
	assert(icmp_parse_reply(packet, sizeof(packet), 42, &router.sa, &target.sa, &reply));
}

static void test_routes_and_interfaces(void)
{
	struct pingu_route v4 = { .metric = 100 }, v6 = { .metric = 200 };
	struct list_head routes;
	struct pingu_iface *iface = pingu_iface_get_by_name_or_new("test0");
	union sockaddr_any global = address(AF_INET6, "2001:db8::1");
	union sockaddr_any link = address(AF_INET6, "fe80::1");
	union sockaddr_any ip4 = address(AF_INET, "192.0.2.1");
	struct ev_loop *loop = ev_loop_new(0);

	sockaddr_init(&v4.dest, AF_INET, NULL);
	sockaddr_init(&v6.dest, AF_INET6, NULL);
	assert(is_default_gw(&v4) && is_default_gw(&v6));
	v6.dst_len = 64;
	assert(!is_default_gw(&v6));
	v6.dst_len = 0;
	list_init(&routes);
	pingu_route_add(&routes, &v4);
	pingu_route_add(&routes, &v6);
	assert(pingu_route_first_default(&routes, AF_INET6)->metric == 200);
	assert(pingu_route_first_default(&routes, AF_INET)->metric == 100);
	pingu_route_del(&routes, &v6); /* Gateway-less routes compare correctly. */
	assert(!pingu_route_first_default(&routes, AF_INET6));
	pingu_route_cleanup(&routes);

	iface->index = 7;
	assert(pingu_iface_update_addr(iface, AF_INET, &ip4.sin.sin_addr, 4, 1));
	assert(pingu_iface_update_addr(iface, AF_INET6, &link.sin6.sin6_addr, 16, 1));
	assert(iface->ipv6.primary_addr.sin6.sin6_scope_id == 7);
	assert(pingu_iface_update_addr(iface, AF_INET6, &global.sin6.sin6_addr, 16, 1));
	assert(sockaddr_cmp(&iface->ipv6.primary_addr, &global) == 0);
	assert(!pingu_iface_update_addr(iface, AF_INET6, &global.sin6.sin6_addr, 4, 1));
	assert(pingu_iface_update_addr(iface, AF_INET6, &global.sin6.sin6_addr, 16, 0));
	assert(IN6_IS_ADDR_LINKLOCAL(&iface->ipv6.primary_addr.sin6.sin6_addr));
	assert(sockaddr_cmp(&iface->ipv4.primary_addr, &ip4) == 0);
	assert(pingu_iface_update_addr(iface, AF_INET6, &link.sin6.sin6_addr, 16, 0));
	assert(iface->ipv6.primary_addr.sa.sa_family == AF_UNSPEC);
	assert(sockaddr_cmp(&iface->ipv4.primary_addr, &ip4) == 0);
	pingu_iface_cleanup(loop);
	ev_loop_destroy(loop);
}

int main(void)
{
	test_addresses();
	test_echo(AF_INET, 69);
	test_echo(AF_INET6, 1281);
	test_echo(AF_INET6, 9000);
	test_packet_too_big();
	test_routes_and_interfaces();
	puts("PASS: IPv4/IPv6 addresses, ICMP packets, malformed replies and interface state");
	return 0;
}
