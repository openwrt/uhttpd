/*
 * uhttpd - Tiny single-threaded httpd - Main header
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

#ifndef __UHTTPD_H
#define __UHTTPD_H

#include <netinet/in.h>
#include <limits.h>
#include <dirent.h>

#include <libubox/list.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/blob.h>
#include <libubox/utils.h>

#include "utils.h"

#define UH_LIMIT_CLIENTS	64
#define UH_LIMIT_HEADERS	64
#define UH_LIMIT_MSGHEAD	4096

struct config {
	char docroot[PATH_MAX];
	char *realm;
	char *file;
	char *error_handler;
	char *cgi_prefix;
	int no_symlinks;
	int no_dirlists;
	int network_timeout;
	int rfc1918_filter;
	int tcp_keepalive;
	int max_requests;
	int http_keepalive;
	int script_timeout;
};

struct auth_realm {
	struct list_head list;
	char *path;
	char *user;
	char *pass;
};

enum http_method {
	UH_HTTP_MSG_GET,
	UH_HTTP_MSG_POST,
	UH_HTTP_MSG_HEAD,
};

enum http_version {
	UH_HTTP_VER_0_9,
	UH_HTTP_VER_1_0,
	UH_HTTP_VER_1_1,
};

struct http_request {
	enum http_method method;
	enum http_version version;
	int redirect_status;
	char *url;
	struct auth_realm *realm;
};

struct http_response {
	int statuscode;
	char *statusmsg;
	char *headers[UH_LIMIT_HEADERS];
};

enum client_state {
	CLIENT_STATE_INIT,
	CLIENT_STATE_HEADER,
	CLIENT_STATE_DATA,
	CLIENT_STATE_DONE,
	CLIENT_STATE_CLOSE,
};

struct client {
	struct list_head list;
	int id;

	struct ustream *us;
	struct ustream_fd sfd;
#ifdef HAVE_TLS
	struct ustream_ssl stream_ssl;
#endif
	struct uloop_fd rpipe;
	struct uloop_fd wpipe;
	struct uloop_process proc;
	struct uloop_timeout timeout;
	bool (*cb)(struct client *);
	void *priv;

	enum client_state state;

	struct http_request request;
	struct http_response response;
	struct sockaddr_in6 servaddr;
	struct sockaddr_in6 peeraddr;

	struct blob_buf hdr;

	struct {
		void (*write_cb)(struct client *cl);
		void (*close_fds)(struct client *cl);
		void (*free)(struct client *cl);
		union {
			struct {
				struct blob_attr **hdr;
				int fd;
			} file;
		};
	} dispatch;
};

extern int n_clients;
extern struct config conf;

void uh_index_add(const char *filename);

void uh_accept_client(int fd);

void uh_unblock_listeners(void);
void uh_setup_listeners(void);
int uh_socket_bind(const char *host, const char *port, bool tls);

bool uh_use_chunked(struct client *cl);
void uh_chunk_write(struct client *cl, const void *data, int len);
void uh_chunk_vprintf(struct client *cl, const char *format, va_list arg);

void __printf(2, 3)
uh_chunk_printf(struct client *cl, const char *format, ...);

void uh_chunk_eof(struct client *cl);
void uh_request_done(struct client *cl);

void uh_http_header(struct client *cl, int code, const char *summary);
void __printf(4, 5)
uh_client_error(struct client *cl, int code, const char *summary, const char *fmt, ...);

void uh_handle_file_request(struct client *cl);

void uh_auth_add(const char *path, const char *user, const char *pass);

void uh_close_listen_fds(void);
void uh_close_fds(void);

#endif
