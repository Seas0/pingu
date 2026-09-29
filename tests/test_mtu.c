/* Exercise discovery with simulated ICMP replies, without raw sockets or
 * network namespaces. Include the CLI to test the same static discovery path. */
#define main mtu_main
#include "../src/mtu.c"
#undef main

#include <assert.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>

static int path_mtu, link_mtu, probe_size, probe_seq, largest_probe;

int __wrap_icmp_send_ping(int sock, struct sockaddr *target, int tolen,
			 int seq, int total_size, const struct sockaddr *source)
{
	assert(target->sa_family == AF_INET6);
	assert(total_size <= 9000);
	if (total_size > largest_probe)
		largest_probe = total_size;
	if (total_size > link_mtu) {
		errno = EMSGSIZE;
		return -1;
	}
	probe_size = total_size;
	probe_seq = seq;
	return 0;
}

int __wrap_icmp_read_reply(int sock, struct sockaddr *from, socklen_t fromlen,
			  __u8 *buf, int buflen, struct sockaddr *local)
{
	struct icmp6_hdr echo = { .icmp6_type = ICMP6_ECHO_REPLY };
	int len = probe_size - sizeof(struct ip6_hdr);

	echo.icmp6_id = htons((uint16_t)getpid());
	echo.icmp6_seq = htons(probe_seq);
	assert(fromlen >= sizeof(to.sin6));
	memcpy(from, &to.sin6, sizeof(to.sin6));
	if (probe_size > path_mtu) {
		struct icmp6_hdr error = { .icmp6_type = ICMP6_PACKET_TOO_BIG };
		struct ip6_hdr quoted = { 0 };
		error.icmp6_mtu = htonl(path_mtu);
		quoted.ip6_vfc = 0x60;
		quoted.ip6_nxt = IPPROTO_ICMPV6;
		quoted.ip6_dst = to.sin6.sin6_addr;
		echo.icmp6_type = ICMP6_ECHO_REQUEST;
		len = sizeof(error) + sizeof(quoted) + sizeof(echo);
		assert(buflen >= len);
		memcpy(buf, &error, sizeof(error));
		memcpy(buf + sizeof(error), &quoted, sizeof(quoted));
		memcpy(buf + sizeof(error) + sizeof(quoted), &echo, sizeof(echo));
	} else {
		/* A buffer too small for jumbo replies must fail the test. */
		assert(buflen >= len);
		memset(buf, 0, len);
		memcpy(buf, &echo, sizeof(echo));
	}
	return len;
}

static void test_discovery(int link, int path, const char *diagnostic)
{
	FILE *output = tmpfile();
	char text[8192], final[32];
	int saved_stdout = dup(STDOUT_FILENO);
	size_t len;

	assert(output && saved_stdout >= 0);
	link_mtu = link;
	path_mtu = path;
	largest_probe = 0;
	fflush(stdout);
	assert(dup2(fileno(output), STDOUT_FILENO) >= 0);
	assert(do_discover() == 0);
	fflush(stdout);
	assert(dup2(saved_stdout, STDOUT_FILENO) >= 0);
	close(saved_stdout);
	rewind(output);
	len = fread(text, 1, sizeof(text) - 1, output);
	text[len] = '\0';
	fclose(output);
	snprintf(final, sizeof(final), "\n%d\n", path);
	assert(len >= strlen(final));
	assert(!strcmp(text + len - strlen(final), final));
	assert(strstr(text, "From 2001:db8::2: icmp_seq=1 bytes=1240\n"));
	if (diagnostic)
		assert(strstr(text, diagnostic));
	assert(largest_probe >= path);
}

int main(void)
{
	sockaddr_init(&to, AF_INET6, NULL);
	assert(inet_pton(AF_INET6, "2001:db8::2", &to.sin6.sin6_addr) == 1);
	test_discovery(9000, 9000, "bytes=8960\n");
	test_discovery(8501, 8501, "bytes=8461\n");
	test_discovery(9000, 6001, "Packet too big (mtu = 6001)\n");
	test_discovery(9000, 1500, "Packet too big (mtu = 1500)\n");
	test_discovery(9000, 1280, "Packet too big (mtu = 1280)\n");
	puts("PASS: IPv6 discovery at 9000/8501/6001/1500/1280 bytes and probe output");
	return 0;
}
