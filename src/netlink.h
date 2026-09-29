#ifndef PINGU_NETLINK_H
#define PINGU_NETLINK_H

#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>

int netlink_route_get(struct sockaddr *dst, uint32_t *mtu, char *ifname);

#endif
