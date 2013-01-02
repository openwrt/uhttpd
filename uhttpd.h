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

#define __enum_header(_name) HDR_##_name,
#define __blobmsg_header(_name) [HDR_##_name] = { .name = #_name, .type = BLOBMSG_TYPE_STRING },

struct client;

struct config {
	const char *docroot;
	const char *realm;
	const char *file;
	const char *error_handler;
	const char *cgi_prefix;
	const char *cgi_path;
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
	const char *path;
	const char *user;
	const char *pass;
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
	const char *url;
	const struct auth_realm *realm;
};

enum client_state {
	CLIENT_STATE_INIT,
	CLIENT_STATE_HEADER,
	CLIENT_STATE_DATA,
	CLIENT_STATE_DONE,
	CLIENT_STATE_CLOSE,
};

struct interpreter {
	struct list_head list;
	const char *path;
	const char *ext;
};

struct path_info {
	const char *root;
	const char *phys;
	const char *name;
	const char *info;
	const char *query;
	bool redirected;
	struct stat stat;
	const struct interpreter *ip;
};

struct env_var {
	const char *name;
	const char *value;
};

struct relay {
	struct ustream_fd sfd;
	struct uloop_process proc;
	struct client *cl;

	bool process_done;
	int ret;
	int header_ofs;

	void (*header_cb)(struct relay *r, const char *name, const char *value);
	void (*header_end)(struct relay *r);
	void (*close)(struct relay *r, int ret);
};

struct dispatch_handler {
	struct list_head list;

	bool (*check_url)(const char *url);
	bool (*check_path)(struct path_info *pi, const char *url);
	void (*handle_request)(struct client *cl, const char *url, struct path_info *pi);
};

struct uh_addr {
	uint8_t family;
	uint16_t port;
	union {
		struct in_addr in;
		struct in6_addr in6;
	};
};

struct client {
	struct list_head list;
	int id;

	struct ustream *us;
	struct ustream_fd sfd;
#ifdef HAVE_TLS
	struct ustream_ssl stream_ssl;
#endif
	struct uloop_timeout timeout;

	enum client_state state;

	struct http_request request;
	struct uh_addr srv_addr, peer_addr;

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
			struct {
				struct blob_buf hdr;
				struct relay r;
				int status_code;
				char *status_msg;
			} proc;
		};
	} dispatch;
};

extern char uh_buf[4096];
extern int n_clients;
extern struct config conf;
extern const char * const http_versions[];
extern const char * const http_methods[];
extern struct dispatch_handler cgi_dispatch;

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

void uh_handle_request(struct client *cl);

void uh_auth_add(const char *path, const char *user, const char *pass);

void uh_close_listen_fds(void);
void uh_close_fds(void);

void uh_interpreter_add(const char *ext, const char *path);
void uh_dispatch_add(struct dispatch_handler *d);

void uh_relay_open(struct client *cl, struct relay *r, int fd, int pid);
void uh_relay_close(struct relay *r, int ret);
void uh_relay_free(struct relay *r);

struct env_var *uh_get_process_vars(struct client *cl, struct path_info *pi);
bool uh_create_process(struct client *cl, struct path_info *pi,
		       void (*cb)(struct client *cl, struct path_info *pi, int fd));

#endif
