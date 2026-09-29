
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

#include "log.h"
#include "sockaddr_util.h"

int sockaddr_cmp(union sockaddr_any *a, union sockaddr_any *b)
{
	if (a->sa.sa_family != b->sa.sa_family)
		return a->sa.sa_family - b->sa.sa_family;
	
	switch (a->sa.sa_family) {
	case AF_INET:
		return memcmp(&a->sin.sin_addr, &b->sin.sin_addr,
			      sizeof(a->sin.sin_addr));
	case AF_INET6:
		if (a->sin6.sin6_scope_id != b->sin6.sin6_scope_id)
			return a->sin6.sin6_scope_id < b->sin6.sin6_scope_id ? -1 : 1;
		return memcmp(&a->sin6.sin6_addr, &b->sin6.sin6_addr,
			      sizeof(a->sin6.sin6_addr));
	case AF_UNSPEC:
		return 0;
	}
	return -1;
}

union sockaddr_any *sockaddr_set4(union sockaddr_any *sa, void *addr)
{
	sa->sa.sa_family = AF_INET;
	memcpy(&sa->sin.sin_addr, addr, sizeof(sa->sin.sin_addr));
	return sa;
}

union sockaddr_any *sockaddr_set6(union sockaddr_any *sa, void *addr)
{
	sa->sa.sa_family = AF_INET6;
	memcpy(&sa->sin6.sin6_addr, addr, sizeof(sa->sin6.sin6_addr));
	return sa;
}

union sockaddr_any *sockaddr_init(union sockaddr_any *sa, int family,
				  void *addr)
{
	memset(sa, 0, sizeof(*sa));
	if (family != AF_INET && family != AF_INET6 && family != AF_UNSPEC)
		return NULL;
	sa->sa.sa_family = family;
	if (addr == NULL)
		return sa;
	switch (family) {
	case AF_INET:
		return sockaddr_set4(sa, addr);
		break;
	case AF_INET6:
		return sockaddr_set6(sa, addr);
		break;
	}
	return NULL;
}

union sockaddr_any *sockaddr_from_addrinfo(union sockaddr_any *sa, 
					     struct addrinfo *ai)
{
	memset(sa, 0, sizeof(*sa));
	if (ai == NULL)
		return sa;
	switch (ai->ai_family) {
	case AF_INET:
		if (ai->ai_addrlen < sizeof(sa->sin))
			return NULL;
		memcpy(&sa->sin, ai->ai_addr, sizeof(sa->sin));
		return sa;
	case AF_INET6:
		if (ai->ai_addrlen < sizeof(sa->sin6))
			return NULL;
		memcpy(&sa->sin6, ai->ai_addr, sizeof(sa->sin6));
		return sa;
	}
	return NULL;
}

char *sockaddr_to_string(union sockaddr_any *sa, char *str, size_t size)
{
	if (size == 0)
		return str;
	str[0] = '\0';
	switch (sa->sa.sa_family) {
	case AF_INET:
		inet_ntop(sa->sa.sa_family, &sa->sin.sin_addr, str, size);
		break;
	case AF_INET6:
		inet_ntop(sa->sa.sa_family, &sa->sin6.sin6_addr, str, size);
		if (sa->sin6.sin6_scope_id) {
			size_t len = strlen(str);
			snprintf(str + len, size - len, "%%%u", sa->sin6.sin6_scope_id);
		}
		break;
	}
	return str;
}

socklen_t sockaddr_len(union sockaddr_any *sa)
{
	socklen_t len = 0;
	switch (sa->sa.sa_family) {
	case AF_INET:
		len = sizeof(sa->sin);
		break;
	case AF_INET6:
		len = sizeof(sa->sin6);
		break;
	}
	return len;
}
