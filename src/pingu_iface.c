
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#include <ev.h>

#include "list.h"
#include "log.h"
#include "pingu_burst.h"
#include "pingu_host.h"
#include "pingu_iface.h"
#include "pingu_ping.h"
#include "pingu_netlink.h"
#include "sockaddr_util.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_STRLCPY
#define	strlcpy(dst, src, dstsize)	snprintf(dst, dstsize, "%s", src)
#endif

static struct list_head iface_list = LIST_INITIALIZER(iface_list);

#define PINGU_ROUTE_TABLE_MIN 1
#define PINGU_ROUTE_TABLE_MAX 253
unsigned char used_route_table[256];

/* do we have any load-balance at all? */
static int load_balanced = 0;

struct pingu_iface_family *pingu_iface_family(struct pingu_iface *iface, int family)
{
	switch (family) {
	case AF_INET:
		return &iface->ipv4;
	case AF_INET6:
		return &iface->ipv6;
	}
	return NULL;
}

static void pingu_iface_socket_cb(struct ev_loop *loop, struct ev_io *w,
				 int revents)
{
	struct pingu_iface_family *state = container_of(w, struct pingu_iface_family, socket_watcher);

	if (revents & EV_READ)
		pingu_ping_read_reply(loop, state->iface, state->family);
}

int pingu_iface_bind_socket(struct pingu_iface *iface, int family, int log_error)
{
	struct pingu_iface_family *state = pingu_iface_family(iface, family);
	int r;

	if (!state || state->fd < 0)
		return -1;
	if (iface->name[0] == '\0')
		return 0;
	state->has_binding = 0;
	r = setsockopt(state->fd, SOL_SOCKET, SO_BINDTODEVICE, iface->name,
		       strlen(iface->name) + 1);
	if (r < 0)
		goto out;
	if (state->primary_addr.sa.sa_family != family)
		return -1;
	/* IPv6 uses per-packet source addresses so link-local and global
	 * probes can share the socket without changing its receive filter. */
	if (family == AF_INET)
		r = bind(state->fd, &state->primary_addr.sa,
			 sockaddr_len(&state->primary_addr));
out:
	if (r < 0 && log_error)
		log_perror(iface->name);
	state->has_binding = (r == 0);
	return r;
}

static int pingu_iface_init_socket(struct ev_loop *loop,
				   struct pingu_iface_family *state)
{
	state->fd = socket(state->family, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
			   state->family == AF_INET6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP);
	if (state->fd < 0) {
		if (state->family == AF_INET6 &&
		    (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT))
			return 0;
		log_perror("socket");
		return -1;
	}

	ev_io_init(&state->socket_watcher, pingu_iface_socket_cb, state->fd, EV_READ);
	ev_io_start(loop, &state->socket_watcher);
	return 0;
}

int pingu_iface_usable(struct pingu_iface *iface, int family)
{
	struct pingu_iface_family *state = pingu_iface_family(iface, family);
	if (!state || state->fd < 0)
		return 0;
	if (iface->name[0] == '\0')
		return 1;
	return iface->has_link && state->primary_addr.sa.sa_family == family && state->has_binding;
}

struct pingu_iface *pingu_iface_get_by_name(const char *name)
{
	struct pingu_iface *iface;
	list_for_each_entry(iface, &iface_list, iface_list_entry) {
		if (name == NULL) {
			if (iface->name[0] == '\0')
				return iface;
		} else if (strncmp(name, iface->name, sizeof(iface->name)) == 0) {
			return iface;
		}
	}
	return NULL;
}

struct pingu_iface *pingu_iface_get_by_index(int index)
{
	struct pingu_iface *iface;
	list_for_each_entry(iface, &iface_list, iface_list_entry) {
		if (iface->index == index)
			return iface;
	}
	return NULL;
}

struct pingu_iface *pingu_iface_get_by_name_or_new(const char *name)
{
	struct pingu_iface *iface = pingu_iface_get_by_name(name);
	if (iface != NULL)
		return iface;

	iface = calloc(1, sizeof(struct pingu_iface));
	if (iface == NULL) {
		log_perror("calloc(iface)");
		return NULL;
	}

	if (name != NULL)
		strlcpy(iface->name, name, sizeof(iface->name));

	iface->ipv4.iface = iface->ipv6.iface = iface;
	iface->ipv4.family = AF_INET;
	iface->ipv6.family = AF_INET6;
	iface->ipv4.fd = iface->ipv6.fd = -1;
	list_init(&iface->ipv4.addresses);
	list_init(&iface->ipv6.addresses);
	list_init(&iface->ping_list);
	list_init(&iface->route_list);
	list_add(&iface->iface_list_entry, &iface_list);
	return iface;
}

int pingu_iface_update_addr(struct pingu_iface *iface, int family,
			    void *data, int len, int add)
{
	struct pingu_iface_family *state = pingu_iface_family(iface, family);
	struct pingu_iface_addr *entry, *next;
	union sockaddr_any addr, primary;
	char buf[80];
	int found = 0;

	if (!state || !data || len != (family == AF_INET6 ? 16 : 4))
		return 0;
	sockaddr_init(&addr, family, data);
	if (family == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&addr.sin6.sin6_addr))
		addr.sin6.sin6_scope_id = iface->index;
	list_for_each_entry_safe(entry, next, &state->addresses, entry) {
		if (sockaddr_cmp(&addr, &entry->addr) != 0)
			continue;
		found = 1;
		if (!add) {
			list_del(&entry->entry);
			free(entry);
		}
		break;
	}
	if (add && !found) {
		entry = calloc(1, sizeof(*entry));
		if (!entry)
			return 0;
		entry->addr = addr;
		list_add_tail(&entry->entry, &state->addresses);
	}
	memset(&primary, 0, sizeof(primary));
	list_for_each_entry(entry, &state->addresses, entry) {
		if (primary.sa.sa_family == AF_UNSPEC ||
		    (family == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&primary.sin6.sin6_addr) &&
		     !IN6_IS_ADDR_LINKLOCAL(&entry->addr.sin6.sin6_addr)))
			primary = entry->addr;
	}
	if (sockaddr_cmp(&primary, &state->primary_addr) == 0)
		return 0;
	state->primary_addr = primary;
	state->has_binding = 0;
	log_debug("%s: IPv%i primary address: %s", iface->name,
		  family == AF_INET6 ? 6 : 4,
		  primary.sa.sa_family ? sockaddr_to_string(&primary, buf, sizeof(buf)) : "removed");
	return 1;
}

void pingu_iface_set_balance(struct pingu_iface *iface, int balance_weight)
{
	load_balanced++;
	iface->balance = 1;
	iface->balance_weight = balance_weight;
}

#if 0
void pingu_route_dump(struct pingu_iface *iface)
{
	struct pingu_route *gw;
	list_for_each_entry(gw, &iface->route_list, route_list_entry) {
		char buf[64];
		sockaddr_to_string(&gw->gw_addr, buf, sizeof(buf));
		log_debug("dump: %s: via %s metric %i", iface->name, buf,
			  gw->metric);
	}
}
#endif

void pingu_iface_gw_action(struct pingu_iface *iface,
			 struct pingu_route *gw, int action)
{
	switch (action) {
	case RTM_NEWROUTE:
		pingu_route_add(&iface->route_list, gw);
		log_debug("%s: added route", iface->name);
		/* if we get a new default gateway for an interface
		 * that is marked "down", remove the default gw again
		 * from main table and let pingu detect that it went up
		 *
		 * This solves the case when dhcp will renew a lease,
		 * recreates the default gw and ISP is broke a bit
		 * futher down the road.
		 */
		if (is_default_gw(gw) && !pingu_iface_gw_is_online(iface)) {
			pingu_iface_update_routes(iface, RTM_DELROUTE,
						  load_balanced > 1);
			/* avoid doing the multipath twice*/
			return;
		}
		break;
	case RTM_DELROUTE:
		pingu_route_del(&iface->route_list, gw);
		log_debug("%s: removed route", iface->name);
		break;
	}
	if (load_balanced > 1 && is_default_gw(gw))
		kernel_route_multipath(RTM_NEWROUTE, &iface_list, RT_TABLE_MAIN);
}

void pingu_iface_update_routes(struct pingu_iface *iface, int action,
			       int do_multipath)
{
	struct pingu_route *route;
	list_for_each_entry(route, &iface->route_list, route_list_entry) {
		if (is_default_gw(route) &&
		    pingu_iface_family(iface, route->dest.sa.sa_family)->primary_addr.sa.sa_family)
			kernel_route_modify(action, route, RT_TABLE_MAIN);
	}
	if (do_multipath)
		kernel_route_multipath(RTM_NEWROUTE, &iface_list, RT_TABLE_MAIN);
}

int pingu_iface_gw_is_online(struct pingu_iface *iface)
{
	return iface->hosts_online >= iface->required_hosts_online;
}

/* check if we should bring up/down this ISP */
void pingu_iface_adjust_hosts_online(struct pingu_iface *iface, int adjustment)
{
	int old_status, new_status, route_action;
	char *action, *statusstr;

	old_status = pingu_iface_gw_is_online(iface);
	iface->hosts_online += adjustment;
	new_status = pingu_iface_gw_is_online(iface);

	if (old_status == new_status)
		return;

	if (new_status) {
		statusstr = "ONLINE";
		route_action = RTM_NEWROUTE;
		action = iface->gw_up_action;
	} else {
		statusstr = "OFFLINE";
		route_action = RTM_DELROUTE;
		action = iface->gw_down_action;
	}

	log_info("%s: went %s", iface->label ? iface->label : iface->name,
		 statusstr);
	pingu_iface_update_routes(iface, route_action, load_balanced > 1);
	execute_action(action);
}

int pingu_iface_set_route_table(struct pingu_iface *iface, int table)
{
	static int initialized = 0;
	int i = 1;
	if (!initialized) {
		memset(used_route_table, 0, sizeof(used_route_table));
		initialized = 1;
	}
	if (table == PINGU_ROUTE_TABLE_AUTO) {
		while (i < 253 && used_route_table[i])
			i++;
		table = i;
	}
	if (table < PINGU_ROUTE_TABLE_MIN || table >= PINGU_ROUTE_TABLE_MAX) {
		log_error("Invalid route table %i", table);
		return -1;
	}
	used_route_table[table] = 1;
	iface->route_table = table;
	return table;
}

void pingu_iface_dump_status(int fd, char *filter)
{
	struct pingu_iface *iface;
	char buf[512];
	list_for_each_entry(iface, &iface_list, iface_list_entry) {
		if (filter != NULL && strcmp(filter, iface->label) != 0)
			continue;
		snprintf(buf, sizeof(buf), "%s: %i\n",
			 iface->label != NULL ? iface->label : iface->name,
			 pingu_iface_gw_is_online(iface));
		write(fd, buf, strlen(buf));
	}
	write(fd, "\n", 1);
}

void pingu_iface_dump_pings(int fd, char *filter)
{
	struct pingu_iface *iface;
	list_for_each_entry(iface, &iface_list, iface_list_entry) {
		if (filter != NULL && strcmp(filter, iface->name) != 0)
			continue;
		pingu_ping_dump(fd, &iface->ping_list, iface->name);
	}
	write(fd, "\n", 1);
}

void pingu_iface_dump_routes(int fd, char *filter)
{
	struct pingu_iface *iface;
	list_for_each_entry(iface, &iface_list, iface_list_entry) {
		if (filter != NULL && strcmp(filter, iface->name) != 0)
			continue;
		pingu_route_dump(fd, &iface->route_list);
	}
	write(fd, "\n", 1);
}

int pingu_iface_init(struct ev_loop *loop)
{
	struct pingu_iface *iface;
	list_for_each_entry(iface, &iface_list, iface_list_entry) {
		if (iface->route_table == 0)
			pingu_iface_set_route_table(iface, PINGU_ROUTE_TABLE_AUTO);
		if (pingu_iface_init_socket(loop, &iface->ipv4) == -1 ||
		    pingu_iface_init_socket(loop, &iface->ipv6) == -1)
			return -1;
	}
	if (load_balanced == 1)
		log_warning("Only a single interface was configured with load-balance");
	return 0;
}

void pingu_iface_cleanup(struct ev_loop *loop)
{
	struct pingu_iface *iface, *n;
	/* remove loadbalance route */
	if (load_balanced > 1) {
		int err = kernel_route_multipath(RTM_DELROUTE, &iface_list, RT_TABLE_MAIN);
		if (err > 0)
			log_error("Failed to delete load-balance route: %s", strerror(err));
	}

	list_for_each_entry(iface, &iface_list, iface_list_entry) {
		/* restore main route table */
		if (!pingu_iface_gw_is_online(iface))
			pingu_iface_update_routes(iface, RTM_NEWROUTE, 0);
		kernel_cleanup_iface_routes(iface);
		struct pingu_iface_family *states[] = { &iface->ipv4, &iface->ipv6 };
		int i;
		for (i = 0; i < 2; i++) {
			struct pingu_iface_addr *addr, *next;
			if (states[i]->fd >= 0) {
				ev_io_stop(loop, &states[i]->socket_watcher);
				close(states[i]->fd);
			}
			list_for_each_entry_safe(addr, next, &states[i]->addresses, entry) {
				list_del(&addr->entry);
				free(addr);
			}
		}
	}
	list_for_each_entry_safe(iface, n, &iface_list, iface_list_entry) {
		list_del(&iface->iface_list_entry);
		if (iface->label != NULL)
			free(iface->label);
		if (iface->gw_up_action != NULL)
			free(iface->gw_up_action);
		if (iface->gw_down_action != NULL)
			free(iface->gw_down_action);
		pingu_ping_cleanup(loop, &iface->ping_list);
		pingu_route_cleanup(&iface->route_list);
		free(iface);
	}
}
