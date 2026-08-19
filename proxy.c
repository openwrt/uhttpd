/*
 * uhttpd - Tiny single-threaded httpd - reverse proxy handler
 *
 *   Copyright (C) 2010-2013 Jo-Philipp Wich <xm@subsignal.org>
 *   Copyright (C) 2013 Felix Fietkau <nbd@openwrt.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <libubox/blobmsg.h>
#include <libubox/usock.h>

#include "uhttpd.h"

#define UH_PROXY_MAX_PENDING	(64 * 1024)

/*
 * RFC 9110 7.6.1: connection-specific fields must not be forwarded by an
 * intermediary.
 */
static const char * const skip_request_headers[] = {
	"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
	"te", "trailer", "transfer-encoding", "upgrade",
	"x-forwarded-for", "x-forwarded-proto", "x-forwarded-host",
	/* internal, they hold the credentials of the proxy's own auth realm */
	"URL", "http-auth-user", "http-auth-pass",
};

static const char * const skip_response_headers[] = {
	"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
	"te", "trailer", "upgrade",
};

static bool
header_in(const char * const *list, size_t len, const char *name, bool upgrade)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (strcasecmp(name, list[i]))
			continue;

		if (upgrade && (!strcasecmp(name, "connection") ||
		                !strcasecmp(name, "upgrade")))
			return false;

		return true;
	}

	return false;
}

static struct proxy_prefix *proxy_match(const char *url)
{
	struct proxy_prefix *px, *match = NULL;

	list_for_each_entry(px, &conf.proxy_prefix, list) {
		char sep = url[px->prefix_len];

		if (strncmp(url, px->prefix, px->prefix_len))
			continue;

		if (sep && sep != '/' && sep != '?')
			continue;

		/* longest matching prefix wins */
		if (match && match->prefix_len >= px->prefix_len)
			continue;

		match = px;
	}

	return match;
}

static bool uh_proxy_check_url(const char *url)
{
	return proxy_match(url) != NULL;
}

/* Handlers selected by check_url() bypass the file request path and with it
 * uh_auth_check(), so a proxy prefix listed in the config file has to be
 * checked here. Credentials are consumed by us and not passed on.
 */
static bool proxy_auth_check(struct client *cl, const char *url)
{
	static const struct blobmsg_policy policy = {
		.name = "authorization", .type = BLOBMSG_TYPE_STRING
	};
	struct blob_attr *tb;
	char path[PATH_MAX];
	const char *sep;
	size_t len;

	sep = strchr(url, '?');
	len = sep ? (size_t)(sep - url) : strlen(url);
	if (len >= sizeof(path))
		len = sizeof(path) - 1;

	memcpy(path, url, len);
	path[len] = 0;

	blobmsg_parse(&policy, 1, &tb, blob_data(cl->hdr.head),
	              blob_len(cl->hdr.head));

	return uh_auth_check(cl, path, tb ? blobmsg_data(tb) : NULL, NULL, NULL);
}

static bool proxy_want_upgrade(struct client *cl)
{
	struct blob_attr *cur;
	bool connection = false, upgrade = false;
	int rem;

	blob_for_each_attr(cur, cl->hdr.head, rem) {
		const char *name = blobmsg_name(cur);

		/* header names in cl->hdr have been lowercased already */
		if (!strcmp(name, "connection")) {
			/* the field is a comma separated list of tokens */
			connection = strcasestr(blobmsg_get_string(cur),
			                        "upgrade") != NULL;
		} else if (!strcmp(name, "upgrade")) {
			upgrade = true;
		}
	}

	return connection && upgrade;
}

static void
proxy_send_request(struct client *cl, struct proxy_prefix *px, const char *url)
{
	struct dispatch_proxy *p = &cl->dispatch.proxy;
	struct ustream *us = &p->r.sfd.stream;
	enum http_version version = cl->request.version;
	char addr[INET6_ADDRSTRLEN];
	struct blob_attr *cur;
	int rem;

	/* Speaking HTTP/1.0 to the backend for a HTTP/1.0 client keeps it from
	 * answering with a chunked body that the client could not decode.
	 */
	if (version == UH_HTTP_VER_0_9)
		version = UH_HTTP_VER_1_0;

	ustream_printf(us, "%s ", http_methods[cl->request.method]);

	if (px->path) {
		const char *rest = url + px->prefix_len;

		ustream_printf(us, "%s%s", px->path, *rest ? rest : "/");
	} else {
		ustream_printf(us, "%s", url);
	}

	ustream_printf(us, " %s\r\n", http_versions[version]);

	blob_for_each_attr(cur, cl->hdr.head, rem) {
		const char *name = blobmsg_name(cur);

		if (header_in(skip_request_headers,
		              ARRAY_SIZE(skip_request_headers), name, p->upgrade))
			continue;

		ustream_printf(us, "%s: %s\r\n", name, blobmsg_get_string(cur));
	}

	if (!p->upgrade)
		ustream_printf(us, "Connection: close\r\n");

	if (p->chunked_req)
		ustream_printf(us, "Transfer-Encoding: chunked\r\n");

	inet_ntop(cl->peer_addr.family, &cl->peer_addr.in, addr, sizeof(addr));
	ustream_printf(us, "X-Forwarded-For: %s\r\n", addr);
	ustream_printf(us, "X-Forwarded-Proto: %s\r\n", cl->tls ? "https" : "http");
	ustream_printf(us, "\r\n");
}

static bool proxy_handle_status(struct relay *r, char *line)
{
	struct dispatch_proxy *p = &r->cl->dispatch.proxy;
	unsigned long code;
	char *end, *msg;

	if (strncmp(line, "HTTP/", 5))
		return false;

	msg = strchr(line, ' ');
	if (!msg)
		return false;

	while (*msg == ' ')
		msg++;

	code = strtoul(msg, &end, 10);
	if (end != msg + 3 || code < 100 || code > 599)
		return false;

	if (*end == ' ')
		end++;
	else if (*end)
		return false;

	p->status_code = (int)code;
	snprintf(p->status_msg, sizeof(p->status_msg), "%s", end);

	return true;
}

static void
proxy_handle_header(struct relay *r, const char *name, const char *val)
{
	struct client *cl = r->cl;
	struct dispatch_proxy *p = &cl->dispatch.proxy;

	if (!strcasecmp(name, "Content-Length") ||
	    !strcasecmp(name, "Transfer-Encoding")) {
		/* the body is relayed as it arrives, uh_chunk_write() must not
		 * add a second layer of framing on top of it */
		p->have_framing = true;
		cl->request.disable_chunked = true;
	}

	if (header_in(skip_response_headers, ARRAY_SIZE(skip_response_headers),
	              name, p->status_code == 101))
		return;

	blobmsg_add_string(&p->hdr, name, val);
}

static void proxy_tunnel_timeout_cb(struct uloop_timeout *timeout)
{
}

static void proxy_handle_header_end(struct relay *r)
{
	struct client *cl = r->cl;
	struct dispatch_proxy *p = &cl->dispatch.proxy;
	struct blob_attr *cur;
	int rem;

	cl->http_code = p->status_code;

	/* RFC 9110 6.4.1, 15.3.5, 15.4.5: these carry no body at all */
	if (p->status_code < 200 || p->status_code == 204 ||
	    p->status_code == 304)
		p->have_framing = true;

	if (p->status_code == 101 && p->upgrade) {
		p->tunnel = true;
		cl->request.disable_chunked = true;
		cl->request.connection_close = true;
	} else if (!p->have_framing && !uh_use_chunked(cl)) {
		/* the response has no framing of its own and none can be added,
		 * so it is delimited by the end of the connection */
		cl->request.connection_close = true;
	}

	ustream_printf(cl->us, "%s %03i %s\r\n",
	               http_versions[cl->request.version],
	               p->status_code, p->status_msg);

	if (!p->tunnel) {
		if (cl->request.connection_close) {
			ustream_printf(cl->us, "Connection: close\r\n");
		} else {
			ustream_printf(cl->us,
			               "Connection: Keep-Alive\r\n"
			               "Keep-Alive: timeout=%d\r\n",
			               conf.http_keepalive);
		}

		if (!p->have_framing && uh_use_chunked(cl))
			ustream_printf(cl->us, "Transfer-Encoding: chunked\r\n");
	}

	blob_for_each_attr(cur, p->hdr.head, rem)
		ustream_printf(cl->us, "%s: %s\r\n", blobmsg_name(cur),
		               blobmsg_get_string(cur));

	ustream_printf(cl->us, "\r\n");

	if (!p->tunnel)
		return;

	/* uh_chunk_write() re-arms the network timeout on every write, which
	 * would tear down a tunnel that is merely idle. Dead peers have to be
	 * detected with TCP keepalive (-A) instead.
	 */
	cl->timeout.cb = proxy_tunnel_timeout_cb;
	cl->state = CLIENT_STATE_TUNNEL;

	/* the client may have pipelined data behind the handshake */
	uloop_timeout_set(&p->poll, 1);
}

static void proxy_handle_close(struct relay *r, int ret)
{
	struct client *cl = r->cl;

	if (r->header_cb) {
		uh_client_error(cl, 502, "Bad Gateway",
		                "The backend did not return a valid response");
		return;
	}

	if (cl->dispatch.proxy.tunnel)
		cl->request.connection_close = true;

	uh_request_done(cl);
}

static int proxy_data_send(struct client *cl, const char *data, int len)
{
	struct dispatch_proxy *p = &cl->dispatch.proxy;
	struct ustream *us = &p->r.sfd.stream;

	if (!p->r.cl || us->write_error)
		return len; /* backend is gone, discard the rest of the body */

	if (ustream_pending_data(us, true) >= UH_PROXY_MAX_PENDING) {
		cl->dispatch.data_blocked = true;
		return 0;
	}

	/* all or nothing, so that the chunk header matches what follows it */
	if (p->chunked_req && !p->tunnel)
		ustream_printf(us, "%X\r\n", len);

	ustream_write(us, data, len, false);

	if (p->chunked_req && !p->tunnel)
		ustream_printf(us, "\r\n");

	return len;
}

static void proxy_data_done(struct client *cl)
{
	struct dispatch_proxy *p = &cl->dispatch.proxy;

	if (p->chunked_req && p->r.cl)
		ustream_printf(&p->r.sfd.stream, "0\r\n\r\n");
}

/* the client connection drained, resume reading from the backend */
static void proxy_relay_write_cb(struct client *cl)
{
	struct dispatch_proxy *p = &cl->dispatch.proxy;

	if (ustream_pending_data(cl->us, true))
		return;

	ustream_set_read_blocked(&p->r.sfd.stream, false);
	p->r.sfd.stream.notify_read(&p->r.sfd.stream, 0);
}

/* the backend connection drained, resume reading from the client */
static void proxy_backend_write_cb(struct ustream *s, int bytes)
{
	struct relay *r = container_of(s, struct relay, sfd.stream);
	struct client *cl = r->cl;

	if (!cl || !cl->dispatch.data_blocked)
		return;

	if (ustream_pending_data(s, true) >= UH_PROXY_MAX_PENDING)
		return;

	cl->dispatch.data_blocked = false;
	uloop_timeout_set(&cl->dispatch.proxy.poll, 1);
}

static void proxy_poll_cb(struct uloop_timeout *timeout)
{
	struct dispatch_proxy *p = container_of(timeout, struct dispatch_proxy, poll);
	struct client *cl = container_of(p, struct client, dispatch.proxy);

	if (p->tunnel)
		uh_client_read_cb(cl);
	else
		client_poll_post_data(cl);

	ustream_poll(cl->us);
}

static void proxy_close_fds(struct client *cl)
{
	struct dispatch_proxy *p = &cl->dispatch.proxy;

	if (p->r.cl)
		close(p->r.sfd.fd.fd);
}

static void proxy_free(struct client *cl)
{
	struct dispatch_proxy *p = &cl->dispatch.proxy;

	uloop_timeout_cancel(&p->poll);
	blob_buf_free(&p->hdr);
	uh_relay_free(&p->r);
}

static void
uh_proxy_handle_request(struct client *cl, char *url, struct path_info *pi)
{
	struct dispatch *d = &cl->dispatch;
	struct dispatch_proxy *p = &d->proxy;
	struct proxy_prefix *px;
	int fd;

	px = proxy_match(url);
	if (!px)
		return uh_client_error(cl, 500, "Internal Server Error",
		                       "No backend for this URL");

	if (!proxy_auth_check(cl, url))
		return;

	/* The socket is handed to the relay before it is connected: writes are
	 * buffered by the ustream until the connection completes, and a failed
	 * connect surfaces as an error on the stream, which is reported as a
	 * 502 by proxy_handle_close().
	 */
	fd = usock(USOCK_TCP | USOCK_NONBLOCK, px->host, px->port);
	if (fd < 0)
		return uh_client_error(cl, 502, "Bad Gateway",
		                       "Unable to connect to the backend");

	blob_buf_init(&p->hdr, 0);
	p->upgrade = proxy_want_upgrade(cl);
	p->chunked_req = cl->request.transfer_chunked != CHUNKED_OFF;

	uh_relay_open_fd(cl, &p->r, fd);

	p->r.header_first = proxy_handle_status;
	p->r.header_cb = proxy_handle_header;
	p->r.header_end = proxy_handle_header_end;
	p->r.close = proxy_handle_close;
	p->r.sfd.stream.notify_write = proxy_backend_write_cb;
	p->poll.cb = proxy_poll_cb;

	d->free = proxy_free;
	d->close_fds = proxy_close_fds;
	d->data_send = proxy_data_send;
	d->data_done = proxy_data_done;
	d->write_cb = proxy_relay_write_cb;

	proxy_send_request(cl, px, url);
}

static struct dispatch_handler proxy_dispatch = {
	.check_url = uh_proxy_check_url,
	.handle_request = uh_proxy_handle_request,
};

void uh_proxy_init(void)
{
	if (list_empty(&conf.proxy_prefix))
		return;

	uh_dispatch_add(&proxy_dispatch);
}

/* prefix=host[:port][/path], with an IPv6 host given in square brackets */
int uh_proxy_add(const char *arg)
{
	struct proxy_prefix *px;
	char *str, *target, *host, *port = NULL, *path = NULL;
	size_t len;

	str = strdup(arg);
	if (!str)
		return -1;

	target = strchr(str, '=');
	if (!target || str[0] != '/')
		goto error;

	*target++ = 0;

	/* strip trailing slashes, "/" becomes a match-all prefix */
	len = strlen(str);
	while (len > 0 && str[len - 1] == '/')
		str[--len] = 0;

	host = target;
	if (*host == '[') {
		host++;
		port = strchr(host, ']');
		if (!port)
			goto error;

		*port++ = 0;
	} else {
		port = host;
	}

	/* The path has to be kept separately: the slash that starts it doubles
	 * as the terminator of the host/port part.
	 */
	path = strchr(port, '/');
	if (path) {
		char *sep = path;

		path = strdup(sep);
		*sep = 0;

		if (!path)
			goto error;
	}

	port = strchr(port, ':');
	if (port)
		*port++ = 0;
	else
		port = "80";

	if (!*host || !*port)
		goto error;

	px = calloc(1, sizeof(*px));
	if (!px)
		goto error;

	px->prefix = str;
	px->prefix_len = len;
	px->host = host;
	px->port = port;

	if (path) {
		/* a trailing slash is contributed by the rest of the URL */
		len = strlen(path);
		while (len > 0 && path[len - 1] == '/')
			path[--len] = 0;

		px->path = path;
	}

	list_add_tail(&px->list, &conf.proxy_prefix);

	return 0;

error:
	free(path);
	free(str);

	return -1;
}
