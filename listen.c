/*
 * uhttpd - Tiny single-threaded httpd
 *
 *   Copyright (C) 2010-2012 Jo-Philipp Wich <xm@subsignal.org>
 *   Copyright (C) 2012 Felix Fietkau <nbd@openwrt.org>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netdb.h>

#include "uhttpd.h"

struct listener {
	struct list_head list;
	struct uloop_fd fd;
	int socket;
	int n_clients;
	struct sockaddr_in6 addr;
	bool tls;
	bool blocked;
};

static LIST_HEAD(listeners);
static int n_blocked;

static void uh_block_listener(struct listener *l)
{
	uloop_fd_delete(&l->fd);
	n_blocked++;
	l->blocked = true;
}

void uh_unblock_listeners(void)
{
	struct listener *l;

	if (!n_blocked && conf.max_requests &&
	    n_clients >= conf.max_requests)
		return;

	list_for_each_entry(l, &listeners, list) {
		if (!l->blocked)
			continue;

		n_blocked--;
		l->blocked = false;
		uloop_fd_add(&l->fd, ULOOP_READ);
	}
}

static void listener_cb(struct uloop_fd *fd, unsigned int events)
{
	struct listener *l = container_of(fd, struct listener, fd);

	uh_accept_client(fd->fd);

	if (conf.max_requests && n_clients >= conf.max_requests)
		uh_block_listener(l);
}

void uh_setup_listeners(void)
{
	struct listener *l;

	list_for_each_entry(l, &listeners, list) {
		l->fd.cb = listener_cb;
		uloop_fd_add(&l->fd, ULOOP_READ);
	}
}

int uh_socket_bind(const char *host, const char *port, bool tls)
{
	int sock = -1;
	int yes = 1;
	int status;
	int bound = 0;
	struct listener *l = NULL;
	struct addrinfo *addrs = NULL, *p = NULL;
	static struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_flags = AI_PASSIVE,
	};

	if ((status = getaddrinfo(host, port, &hints, &addrs)) != 0) {
		fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(status));
		return -1;
	}

	/* try to bind a new socket to each found address */
	for (p = addrs; p; p = p->ai_next) {
		/* get the socket */
		sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (sock < 0) {
			perror("socket()");
			goto error;
		}

		/* "address already in use" */
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes))) {
			perror("setsockopt()");
			goto error;
		}

		/* TCP keep-alive */
		if (conf.tcp_keepalive > 0) {
			int ret = 0;
#ifdef linux
			int tcp_ka_idl, tcp_ka_int, tcp_ka_cnt;

			tcp_ka_idl = 1;
			tcp_ka_cnt = 3;
			tcp_ka_int = conf.tcp_keepalive;
			ret =	setsockopt(sock, SOL_TCP, TCP_KEEPIDLE,  &tcp_ka_idl, sizeof(tcp_ka_idl)) ||
				setsockopt(sock, SOL_TCP, TCP_KEEPINTVL, &tcp_ka_int, sizeof(tcp_ka_int)) ||
				setsockopt(sock, SOL_TCP, TCP_KEEPCNT,   &tcp_ka_cnt, sizeof(tcp_ka_cnt));
#endif

			if (ret || setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes)))
				fprintf(stderr, "Notice: Unable to enable TCP keep-alive: %s\n",
					strerror(errno));
		}

		/* required to get parallel v4 + v6 working */
		if (p->ai_family == AF_INET6 &&
		    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes)) < 0) {
			perror("setsockopt()");
			goto error;
		}

		/* bind */
		if (bind(sock, p->ai_addr, p->ai_addrlen) < 0) {
			perror("bind()");
			goto error;
		}

		/* listen */
		if (listen(sock, UH_LIMIT_CLIENTS) < 0) {
			perror("listen()");
			goto error;
		}

		fd_cloexec(sock);

		l = calloc(1, sizeof(*l));
		if (!l)
			goto error;

		l->fd.fd = sock;
		l->tls = tls;
		list_add_tail(&l->list, &listeners);

		continue;

error:
		if (sock > 0)
			close(sock);
	}

	freeaddrinfo(addrs);

	return bound;
}
