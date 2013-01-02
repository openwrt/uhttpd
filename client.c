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

#include <libubox/blobmsg.h>
#include <ctype.h>

#include "uhttpd.h"

static LIST_HEAD(clients);

int n_clients = 0;
struct config conf = {};

const char * const http_versions[] = {
	[UH_HTTP_VER_0_9] = "HTTP/0.9",
	[UH_HTTP_VER_1_0] = "HTTP/1.0",
	[UH_HTTP_VER_1_1] = "HTTP/1.1",
};

const char * const http_methods[] = {
	[UH_HTTP_MSG_GET] = "GET",
	[UH_HTTP_MSG_POST] = "POST",
	[UH_HTTP_MSG_HEAD] = "HEAD",
};

void uh_http_header(struct client *cl, int code, const char *summary)
{
	const char *enc = "Transfer-Encoding: chunked\r\n";
	const char *conn;

	if (!uh_use_chunked(cl))
		enc = "";

	if (cl->request.version != UH_HTTP_VER_1_1)
		conn = "Connection: close";
	else
		conn = "Connection: keep-alive";

	ustream_printf(cl->us, "%s %03i %s\r\n%s\r\n%s",
		http_versions[cl->request.version],
		code, summary, conn, enc);
}

static void uh_connection_close(struct client *cl)
{
	cl->state = CLIENT_STATE_CLOSE;
	cl->us->eof = true;
	ustream_state_change(cl->us);
}

static void uh_dispatch_done(struct client *cl)
{
	if (cl->dispatch.free)
		cl->dispatch.free(cl);
}

void uh_request_done(struct client *cl)
{
	uh_chunk_eof(cl);
	uh_dispatch_done(cl);
	cl->us->notify_write = NULL;
	memset(&cl->dispatch, 0, sizeof(cl->dispatch));

	if (cl->request.version != UH_HTTP_VER_1_1 || !conf.http_keepalive) {
		uh_connection_close(cl);
		return;
	}

	cl->state = CLIENT_STATE_INIT;
	uloop_timeout_set(&cl->timeout, conf.http_keepalive * 1000);
}

void __printf(4, 5)
uh_client_error(struct client *cl, int code, const char *summary, const char *fmt, ...)
{
	va_list arg;

	uh_http_header(cl, code, summary);
	ustream_printf(cl->us, "Content-Type: text/html\r\n\r\n");

	uh_chunk_printf(cl, "<h1>%s</h1>", summary);

	if (fmt) {
		va_start(arg, fmt);
		uh_chunk_vprintf(cl, fmt, arg);
		va_end(arg);
	}

	uh_request_done(cl);
}

static void uh_header_error(struct client *cl, int code, const char *summary)
{
	uh_client_error(cl, code, summary, NULL);
	uh_connection_close(cl);
}

static void client_timeout(struct uloop_timeout *timeout)
{
	struct client *cl = container_of(timeout, struct client, timeout);

	cl->state = CLIENT_STATE_CLOSE;
	uh_connection_close(cl);
}

static int find_idx(const char * const *list, int max, const char *str)
{
	int i;

	for (i = 0; i < max; i++)
		if (!strcmp(list[i], str))
			return i;

	return -1;
}

static int client_parse_request(struct client *cl, char *data)
{
	struct http_request *req = &cl->request;
	char *type, *path, *version;

	type = strtok(data, " ");
	path = strtok(NULL, " ");
	version = strtok(NULL, " ");
	if (!type || !path || !version)
		return CLIENT_STATE_DONE;

	req->url = path;
	req->method = find_idx(http_methods, ARRAY_SIZE(http_methods), type);
	if (req->method < 0)
		return CLIENT_STATE_DONE;

	req->version = find_idx(http_versions, ARRAY_SIZE(http_versions), version);
	if (cl->request.version < 0)
		return CLIENT_STATE_DONE;

	return CLIENT_STATE_HEADER;
}

static bool client_init_cb(struct client *cl, char *buf, int len)
{
	char *newline;

	newline = strstr(buf, "\r\n");
	if (!newline)
		return false;

	*newline = 0;
	blob_buf_init(&cl->hdr, 0);
	blobmsg_add_string(&cl->hdr, "REQUEST", buf);
	ustream_consume(cl->us, newline + 2 - buf);
	cl->state = client_parse_request(cl, (char *) blobmsg_data(blob_data(cl->hdr.head)));
	if (cl->state == CLIENT_STATE_DONE)
		uh_header_error(cl, 400, "Bad Request");

	return true;
}

static void client_header_complete(struct client *cl)
{
	uh_handle_request(cl);
}

static void client_parse_header(struct client *cl, char *data)
{
	char *name;
	char *val;

	if (!*data) {
		uloop_timeout_cancel(&cl->timeout);
		cl->state = CLIENT_STATE_DATA;
		client_header_complete(cl);
		return;
	}

	val = uh_split_header(data);
	if (!val) {
		cl->state = CLIENT_STATE_DONE;
		return;
	}

	for (name = data; *name; name++)
		if (isupper(*name))
			*name = tolower(*name);

	blobmsg_add_string(&cl->hdr, data, val);

	cl->state = CLIENT_STATE_HEADER;
}

static bool client_data_cb(struct client *cl, char *buf, int len)
{
	return false;
}

static bool client_header_cb(struct client *cl, char *buf, int len)
{
	char *newline;
	int line_len;

	newline = strstr(buf, "\r\n");
	if (!newline)
		return false;

	*newline = 0;
	client_parse_header(cl, buf);
	line_len = newline + 2 - buf;
	ustream_consume(cl->us, line_len);
	if (cl->state == CLIENT_STATE_DATA)
		client_data_cb(cl, newline + 2, len - line_len);

	return true;
}

typedef bool (*read_cb_t)(struct client *cl, char *buf, int len);
static read_cb_t read_cbs[] = {
	[CLIENT_STATE_INIT] = client_init_cb,
	[CLIENT_STATE_HEADER] = client_header_cb,
	[CLIENT_STATE_DATA] = client_data_cb,
};

static void client_read_cb(struct client *cl)
{
	struct ustream *us = cl->us;
	char *str;
	int len;

	do {
		str = ustream_get_read_buf(us, &len);
		if (!str)
			break;

		if (cl->state >= array_size(read_cbs) || !read_cbs[cl->state])
			break;

		if (!read_cbs[cl->state](cl, str, len)) {
			if (len == us->r.buffer_len)
				uh_header_error(cl, 413, "Request Entity Too Large");
			break;
		}
	} while(1);
}

static void client_close(struct client *cl)
{
	uh_dispatch_done(cl);
	uloop_timeout_cancel(&cl->timeout);
	ustream_free(&cl->sfd.stream);
	close(cl->sfd.fd.fd);
	list_del(&cl->list);
	blob_buf_free(&cl->hdr);
	free(cl);

	uh_unblock_listeners();
}

static void client_ustream_read_cb(struct ustream *s, int bytes)
{
	struct client *cl = container_of(s, struct client, sfd);

	client_read_cb(cl);
}

static void client_ustream_write_cb(struct ustream *s, int bytes)
{
	struct client *cl = container_of(s, struct client, sfd);

	if (cl->dispatch.write_cb)
		cl->dispatch.write_cb(cl);
}

static void client_notify_state(struct ustream *s)
{
	struct client *cl = container_of(s, struct client, sfd);

	if (!s->write_error) {
		if (cl->state == CLIENT_STATE_DATA)
			return;

		if (!s->eof || s->w.data_bytes)
			return;
	}

	return client_close(cl);
}

void uh_accept_client(int fd)
{
	static struct client *next_client;
	struct client *cl;
	unsigned int sl;
	int sfd;
	static int client_id = 0;

	if (!next_client)
		next_client = calloc(1, sizeof(*next_client));

	cl = next_client;

	sl = sizeof(cl->peeraddr);
	sfd = accept(fd, (struct sockaddr *) &cl->peeraddr, &sl);
	if (sfd < 0)
		return;

	sl = sizeof(cl->servaddr);
	getsockname(fd, (struct sockaddr *) &cl->servaddr, &sl);
	cl->us = &cl->sfd.stream;
	cl->us->string_data = true;
	cl->us->notify_read = client_ustream_read_cb;
	cl->us->notify_write = client_ustream_write_cb;
	cl->us->notify_state = client_notify_state;
	ustream_fd_init(&cl->sfd, sfd);

	cl->timeout.cb = client_timeout;
	uloop_timeout_set(&cl->timeout, conf.network_timeout * 1000);

	list_add_tail(&cl->list, &clients);

	next_client = NULL;
	n_clients++;
	cl->id = client_id++;
}

void uh_close_fds(void)
{
	struct client *cl;

	uloop_done();
	uh_close_listen_fds();
	list_for_each_entry(cl, &clients, list) {
		close(cl->sfd.fd.fd);
		if (cl->dispatch.close_fds)
			cl->dispatch.close_fds(cl);
	}
}
