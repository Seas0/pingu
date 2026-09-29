#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ev.h>

#include "icmp.h"
#include "list.h"
#include "log.h"
#include "pingu_burst.h"
#include "pingu_host.h"
#include "pingu_iface.h"
#include "pingu_ping.h"
#include "sockaddr_util.h"

#define PING_SEQ_MAX 32000

static int pingu_ping_get_seq(void)
{
	static int seq = 0;
	seq = (seq + 1) % PING_SEQ_MAX;
	return seq;
}

static void pingu_ping_free(struct ev_loop *loop, struct pingu_ping *ping)
{
	list_del(&ping->ping_list_entry);
	ev_timer_stop(loop, &ping->timeout_watcher);
	free(ping);
}

static void pingu_ping_verify_and_free(struct ev_loop *loop, struct pingu_ping *ping)
{
	pingu_host_verify_status(loop, ping->host);
	pingu_ping_free(loop, ping);
}

static void pingu_ping_timeout_cb(struct ev_loop *loop, ev_timer *w,
				  int revents)
{
	struct pingu_ping *ping = container_of(w, struct pingu_ping, timeout_watcher);
	log_debug("%s: seq %i (%i/%i) timed out", ping->host->label, ping->seq,
		ping->host->burst.pings_sent, ping->host->max_retries);
	pingu_ping_verify_and_free(loop, ping);
}

static struct pingu_ping *pingu_ping_add(struct ev_loop *loop,
					 struct pingu_host *host, int seq)
{
	struct pingu_ping *ping = calloc(1, sizeof(struct pingu_ping));
	if (ping == NULL)
		return NULL;
	ping->seq = seq;
	ping->host = host;
	ping->host->burst.pings_sent++;
	ev_timer_init(&ping->timeout_watcher, pingu_ping_timeout_cb,
		      host->timeout, 0);
	ev_timer_start(loop, &ping->timeout_watcher);
	list_add(&ping->ping_list_entry, &host->iface->ping_list);
	return ping;
}

static struct pingu_ping *pingu_ping_find(struct icmp_reply *reply,
					  union sockaddr_any *from,
					  struct list_head *ping_list)
{
	struct pingu_ping *ping;
	if (!reply->echo_reply)
		return NULL;

	list_for_each_entry(ping, ping_list, ping_list_entry) {
		if (sockaddr_cmp(&ping->host->burst.saddr, from) == 0
		    && ping->seq == reply->seq)
			return ping;
	}
	return NULL;
}

static void pingu_ping_handle_reply(struct ev_loop *loop,
				    struct pingu_ping *ping)
{
	ping->host->burst.pings_replied++;
	log_debug("%s: got seq %i (%i/%i)", ping->host->label, ping->seq,
		  ping->host->burst.pings_replied,
		  ping->host->required_replies);
	pingu_ping_verify_and_free(loop, ping);
}

int pingu_ping_send(struct ev_loop *loop, struct pingu_host *host,
		    int set_status_on_failure)
{
	int family = host->burst.saddr.sa.sa_family;
	struct pingu_iface_family *state = pingu_iface_family(host->iface, family);
	union sockaddr_any source;
	struct sockaddr *src = NULL;
	struct pingu_ping *ping;
	int seq, r;

	if (!pingu_iface_usable(host->iface, family)) {
		if (set_status_on_failure)
			pingu_host_set_status(host, PINGU_HOST_STATUS_OFFLINE);
		return -1;
	}
	if (family == AF_INET6 && host->iface->name[0]) {
		source = state->primary_addr;
		if (IN6_IS_ADDR_LINKLOCAL(&host->burst.saddr.sin6.sin6_addr))
			source.sin6.sin6_addr = in6addr_any;
		source.sin6.sin6_scope_id = host->iface->index;
		src = &source.sa;
	}

	seq = pingu_ping_get_seq();
	r = icmp_send_ping(state->fd, &host->burst.saddr.sa,
			       sockaddr_len(&host->burst.saddr), seq, 0, src);
	if (r < 0) {
		if (set_status_on_failure)
			pingu_host_set_status(host, PINGU_HOST_STATUS_OFFLINE);
		return -1;
	}

	ping = pingu_ping_add(loop, host, seq);
	return ping == NULL ? -1 : 0;
}

void pingu_ping_read_reply(struct ev_loop *loop, struct pingu_iface *iface, int family)
{
	union sockaddr_any from = { 0 };
	unsigned char buf[1500];
	struct icmp_reply reply;
	struct pingu_ping *ping;

	int len = icmp_read_reply(pingu_iface_family(iface, family)->fd,
				  &from.sa, sizeof(from), buf, sizeof(buf), NULL);
	if (len <= 0 || icmp_parse_reply(buf, len, -1, &from.sa, NULL, &reply))
		return;
	ping = pingu_ping_find(&reply, &from,
				  &iface->ping_list);
	if (ping == NULL)
		return;

	pingu_ping_handle_reply(loop, ping);
}

void pingu_ping_cleanup(struct ev_loop *loop, struct list_head *ping_list)
{
	struct pingu_ping *ping, *n;
	list_for_each_entry_safe(ping, n, ping_list, ping_list_entry) {
		pingu_ping_free(loop, ping);
	}
}

void pingu_ping_dump(int fd, struct list_head *ping_list, const char *prefix)
{
	struct pingu_ping *ping;
	char str[IF_NAMESIZE + 80];
	list_for_each_entry(ping, ping_list, ping_list_entry) {
		snprintf(str, sizeof(str), "%s %s %i\n",
			 prefix, ping->host->host, ping->seq);
		write(fd, str, strlen(str));
	}
}
