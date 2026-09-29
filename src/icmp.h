#ifndef PINGU_ICMP_H
#define PINGU_ICMP_H

#include <asm/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <stdint.h>

/* Maximum total IP packet size, including the IP header. */
#define ICMP_MAX_PACKET_SIZE 9000

struct icmp_reply {
	int type;
	int code;
	int seq;
	int echo_reply;
	int bytes;
	uint32_t info;
	uint32_t mtu;
};

int icmp_parse_reply(__u8 *buf, int len, int seq,
		     struct sockaddr *addr,
		     struct sockaddr *origdest, struct icmp_reply *reply);
int icmp_send(int fd, struct sockaddr *to, int tolen, void *buf, int buflen);
int icmp_send_frag_needed(int fd, struct sockaddr *to, int tolen,
			  const void *packet, int packetlen,
			  struct sockaddr *local, int newmtu);
int icmp_send_ping(int fd, struct sockaddr *to, int tolen,
		   int seq, int total_size, const struct sockaddr *source);
int icmp_read_reply(int fd, struct sockaddr *from, socklen_t fromlen,
		    __u8 *buf, int buflen, struct sockaddr *local);
int icmp_open(int family, float timeout);
void icmp_close(int fd);


#endif
