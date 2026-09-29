#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "icmp.h"
#include "sockaddr_util.h"

static uint16_t in_cksum(const void *data, size_t len)
{
	const unsigned char *p = data;
	uint32_t sum = 0;

	while (len > 1) {
		sum += (p[0] << 8) | p[1];
		p += 2;
		len -= 2;
	}
	if (len)
		sum += p[0] << 8;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return htons(~sum);
}

/* Locate ICMP in an IP packet, including the packet quoted by an error. */
static int icmp_offset(const unsigned char *buf, int len, int family)
{
	int offset, next;

	if (family == AF_INET) {
		struct iphdr ip;
		if (len < (int)sizeof(ip))
			return -1;
		memcpy(&ip, buf, sizeof(ip));
		offset = ip.ihl * 4;
		if (ip.version != 4 || offset < (int)sizeof(ip) ||
		    offset > len || ip.protocol != IPPROTO_ICMP ||
		    (ntohs(ip.frag_off) & IP_OFFMASK))
			return -1;
		return offset;
	}
	if (family != AF_INET6 || len < (int)sizeof(struct ip6_hdr) ||
	    (buf[0] >> 4) != 6)
		return -1;

	next = buf[6];
	offset = sizeof(struct ip6_hdr);
	while (next != IPPROTO_ICMPV6) {
		int size;
		if (len - offset < 8)
			return -1;
		switch (next) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
			size = (buf[offset + 1] + 1) * 8;
			break;
		case IPPROTO_AH:
			size = (buf[offset + 1] + 2) * 4;
			break;
		case IPPROTO_FRAGMENT:
			/* A non-initial fragment cannot quote an echo header. */
			if (buf[offset + 2] || (buf[offset + 3] & 0xf8))
				return -1;
			size = 8;
			break;
		default:
			return -1;
		}
		if (size > len - offset)
			return -1;
		next = buf[offset];
		offset += size;
	}
	return offset;
}

int icmp_parse_reply(__u8 *buf, int len, int seq, struct sockaddr *addr,
		     struct sockaddr *origdest, struct icmp_reply *reply)
{
	struct icmp6_hdr header, echo;
	int family = addr->sa_family;
	int offset, quoted;

	memset(reply, 0, sizeof(*reply));
	/* Linux raw IPv6 sockets return the payload without the IP header.
	 * The kernel also verifies and generates the ICMPv6 checksum. */
	if (family == AF_INET6)
		offset = 0;
	else if (family == AF_INET)
		offset = icmp_offset(buf, len, family);
	else
		return 1;
	if (offset < 0 || len - offset < (int)sizeof(header))
		return 1;
	if (family == AF_INET && in_cksum(buf + offset, len - offset))
		return 1;
	memcpy(&header, buf + offset, sizeof(header));
	reply->bytes = len - offset;
	reply->info = ntohl(header.icmp6_data32[0]);
	reply->type = header.icmp6_type;
	reply->code = header.icmp6_code;
	reply->echo_reply = header.icmp6_type ==
		(family == AF_INET6 ? ICMP6_ECHO_REPLY : ICMP_ECHOREPLY);
	echo = header;
	if (reply->echo_reply) {
		if (header.icmp6_code != 0 || (origdest &&
		    sockaddr_cmp((union sockaddr_any *)addr,
				 (union sockaddr_any *)origdest)))
			return 1;
	} else {
		if (!origdest || origdest->sa_family != family)
			return 1;
		if (family == AF_INET6) {
			struct ip6_hdr ip;
			if (header.icmp6_type != ICMP6_PACKET_TOO_BIG &&
			    header.icmp6_type != ICMP6_DST_UNREACH &&
			    header.icmp6_type != ICMP6_TIME_EXCEEDED &&
			    header.icmp6_type != ICMP6_PARAM_PROB)
				return 1;
			offset += sizeof(header);
			if (len - offset < (int)sizeof(ip))
				return 1;
			memcpy(&ip, buf + offset, sizeof(ip));
			if (memcmp(&ip.ip6_dst,
				   &((struct sockaddr_in6 *)origdest)->sin6_addr,
				   sizeof(ip.ip6_dst)))
				return 1;
			if (header.icmp6_type == ICMP6_PACKET_TOO_BIG) {
				if (header.icmp6_code)
					return 1;
				reply->mtu = ntohl(header.icmp6_mtu);
			}
		} else {
			struct iphdr ip;
			if (header.icmp6_type != ICMP_DEST_UNREACH &&
			    header.icmp6_type != ICMP_TIME_EXCEEDED &&
			    header.icmp6_type != ICMP_PARAMETERPROB)
				return 1;
			offset += sizeof(header);
			if (len - offset < (int)sizeof(ip))
				return 1;
			memcpy(&ip, buf + offset, sizeof(ip));
			if (ip.daddr != ((struct sockaddr_in *)origdest)->sin_addr.s_addr)
				return 1;
			if (header.icmp6_type == ICMP_DEST_UNREACH &&
			    header.icmp6_code == ICMP_FRAG_NEEDED)
				reply->mtu = ntohs(header.icmp6_data16[1]);
		}
		quoted = icmp_offset(buf + offset, len - offset, family);
		if (quoted < 0 || len - offset - quoted < (int)sizeof(echo))
			return 1;
		memcpy(&echo, buf + offset + quoted, sizeof(echo));
		if (echo.icmp6_type != (family == AF_INET6 ? ICMP6_ECHO_REQUEST : ICMP_ECHO) ||
		    echo.icmp6_code != 0)
			return 1;
	}
	reply->seq = ntohs(echo.icmp6_seq);
	if (echo.icmp6_id != htons((uint16_t)getpid()) ||
	    (seq >= 0 && reply->seq != seq))
		return 1;
	return 0;
}

int icmp_send(int fd, struct sockaddr *to, int tolen, void *buf, int buflen)
{
	return sendto(fd, buf, buflen, 0, to, tolen) == buflen ? 0 : -1;
}

int icmp_send_frag_needed(int fd, struct sockaddr *to, int tolen,
			  const void *original, int original_len,
			  struct sockaddr *local, int newmtu)
{
	unsigned char packet[1280 - sizeof(struct ip6_hdr)] = { 0 };
	struct icmp6_hdr *icmp = (void *)packet;
	int len;

	if (to->sa_family == AF_INET6) {
		struct ip6_hdr *ip = (void *)(icmp + 1);
		int maxquote = sizeof(packet) - sizeof(*icmp) - sizeof(*ip);
		if (!local || local->sa_family != AF_INET6 || original_len < 8 ||
		    newmtu < 1280)
			return -1;
		icmp->icmp6_type = ICMP6_PACKET_TOO_BIG;
		icmp->icmp6_mtu = htonl(newmtu);
		/* Raw ICMPv6 receives no IP header: reconstruct it from pktinfo. */
		ip->ip6_vfc = 0x60;
		ip->ip6_plen = htons(original_len);
		ip->ip6_nxt = IPPROTO_ICMPV6;
		ip->ip6_hlim = 64;
		ip->ip6_src = ((struct sockaddr_in6 *)to)->sin6_addr;
		ip->ip6_dst = ((struct sockaddr_in6 *)local)->sin6_addr;
		if (original_len > maxquote)
			original_len = maxquote;
		memcpy(ip + 1, original, original_len);
		len = sizeof(*icmp) + sizeof(*ip) + original_len;
	} else if (to->sa_family == AF_INET) {
		int hlen = icmp_offset(original, original_len, AF_INET);
		if (hlen < 0 || original_len < hlen + 8)
			return -1;
		icmp->icmp6_type = ICMP_DEST_UNREACH;
		icmp->icmp6_code = ICMP_FRAG_NEEDED;
		icmp->icmp6_data16[1] = htons(newmtu);
		len = sizeof(*icmp) + hlen + 8;
		memcpy(icmp + 1, original, hlen + 8);
		icmp->icmp6_cksum = in_cksum(packet, len);
	} else {
		return -1;
	}
	return icmp_send(fd, to, tolen, packet, len);
}

int icmp_send_ping(int fd, struct sockaddr *to, int tolen,
		   int seq, int total_size, const struct sockaddr *source)
{
	unsigned char packet[ICMP_MAX_PACKET_SIZE];
	struct icmp6_hdr *icmp = (void *)packet;
	int hlen, len;

	if (to->sa_family != AF_INET && to->sa_family != AF_INET6) {
		errno = EAFNOSUPPORT;
		return -1;
	}
	hlen = to->sa_family == AF_INET6 ? sizeof(struct ip6_hdr) : sizeof(struct iphdr);
	if (total_size > (int)sizeof(packet)) {
		errno = EMSGSIZE;
		return -1;
	}
	if (total_size < hlen + (int)sizeof(*icmp))
		total_size = hlen + sizeof(*icmp);
	len = total_size - hlen;
	memset(packet, 0, len);
	icmp->icmp6_type = to->sa_family == AF_INET6 ? ICMP6_ECHO_REQUEST : ICMP_ECHO;
	icmp->icmp6_seq = htons(seq);
	icmp->icmp6_id = htons((uint16_t)getpid());
	if (to->sa_family == AF_INET)
		icmp->icmp6_cksum = in_cksum(packet, len);
	if (source && source->sa_family == AF_INET6) {
		union {
			struct cmsghdr align;
			char buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
		} control = { 0 };
		struct iovec iov = { .iov_base = packet, .iov_len = len };
		struct msghdr msg = {
			.msg_name = to, .msg_namelen = tolen,
			.msg_iov = &iov, .msg_iovlen = 1,
			.msg_control = control.buf, .msg_controllen = sizeof(control.buf),
		};
		struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
		struct in6_pktinfo *info = (void *)CMSG_DATA(cmsg);
		const struct sockaddr_in6 *sin6 = (const void *)source;
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(*info));
		info->ipi6_addr = sin6->sin6_addr;
		info->ipi6_ifindex = sin6->sin6_scope_id;
		return sendmsg(fd, &msg, 0) == len ? 0 : -1;
	}
	return icmp_send(fd, to, tolen, packet, len);
}

int icmp_read_reply(int fd, struct sockaddr *from, socklen_t fromlen,
		    __u8 *buf, int buflen, struct sockaddr *local)
{
	union {
		struct cmsghdr align;
		char buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	} control;
	struct iovec iov = { .iov_base = buf, .iov_len = buflen };
	struct msghdr msg = {
		.msg_name = from, .msg_namelen = fromlen,
		.msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = control.buf, .msg_controllen = sizeof(control.buf),
	};
	struct cmsghdr *cmsg;
	int len = recvmsg(fd, &msg, 0);

	if (len < 0)
		return errno == EAGAIN || errno == EINTR ? 0 : -1;
	if (msg.msg_flags & MSG_TRUNC)
		return 0;
	if (local) {
		local->sa_family = AF_UNSPEC;
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO &&
			    cmsg->cmsg_len >= CMSG_LEN(sizeof(struct in6_pktinfo))) {
				struct in6_pktinfo *info = (void *)CMSG_DATA(cmsg);
				struct sockaddr_in6 *sin6 = (void *)local;
				memset(sin6, 0, sizeof(*sin6));
				sin6->sin6_family = AF_INET6;
				sin6->sin6_addr = info->ipi6_addr;
				sin6->sin6_scope_id = info->ipi6_ifindex;
			}
		}
	}
	return len;
}

int icmp_open(int family, float timeout)
{
	int v6 = family == AF_INET6;
	int pmtudisc = v6 ? IPV6_PMTUDISC_DO : IP_PMTUDISC_DO;
	int on = 1;
	struct timeval tv;
	int fd = socket(family, SOCK_RAW, v6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP);

	if (fd < 0) {
		perror("mtu: socket");
		return -1;
	}
	if (setsockopt(fd, v6 ? IPPROTO_IPV6 : IPPROTO_IP,
		       v6 ? IPV6_MTU_DISCOVER : IP_MTU_DISCOVER,
		       &pmtudisc, sizeof(pmtudisc)) < 0)
		goto err_close;
	if (v6 && setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0)
		goto err_close;
	tv.tv_sec = (time_t)timeout;
	tv.tv_usec = (timeout - tv.tv_sec) * 1000000;
	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0 ||
	    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
		goto err_close;
	return fd;

err_close:
	perror("mtu: setsockopt");
	close(fd);
	return -1;
}

void icmp_close(int fd)
{
	close(fd);
}
