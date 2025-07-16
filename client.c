/*
 * uhttpd - Tiny single-threaded httpd
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

#include <libubox/blobmsg.h>
#include <ctype.h>

#include "uhttpd.h"
#include "tls.h"

static LIST_HEAD(clients);
static bool client_done = false;

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
	[UH_HTTP_MSG_OPTIONS] = "OPTIONS",
	[UH_HTTP_MSG_PUT] = "PUT",
	[UH_HTTP_MSG_PATCH] = "PATCH",
	[UH_HTTP_MSG_DELETE] = "DELETE",
};

void uh_http_header(struct client *cl, int code, const char *summary)
{
	struct http_request *r = &cl->request;
	struct blob_attr *cur;
	const char *enc = "Transfer-Encoding: chunked\r\n";
	const char *conn;
	int rem;

	cl->http_code = code;

	if (!uh_use_chunked(cl))
		enc = "";

	if (r->connection_close)
		conn = "Connection: close";
	else
		conn = "Connection: Keep-Alive";

	ustream_printf(cl->us, "%s %03i %s\r\n%s\r\n%s",
		http_versions[cl->request.version],
		code, summary, conn, enc);

	if (!r->connection_close)
		ustream_printf(cl->us, "Keep-Alive: timeout=%d\r\n", conf.http_keepalive);

	blobmsg_for_each_attr(cur, cl->hdr_response.head, rem)
		ustream_printf(cl->us, "%s: %s\r\n", blobmsg_name(cur),
			       blobmsg_get_string(cur));
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
	if (cl->dispatch.req_free)
		cl->dispatch.req_free(cl);
}

static void client_timeout(struct uloop_timeout *timeout)
{
	struct client *cl = container_of(timeout, struct client, timeout);

	cl->state = CLIENT_STATE_CLOSE;
	cl->request.connection_close = true;
	uh_request_done(cl);
}

static void uh_set_client_timeout(struct client *cl, int timeout)
{
	cl->timeout.cb = client_timeout;
	uloop_timeout_set(&cl->timeout, timeout * 1000);
}

static void uh_keepalive_poll_cb(struct uloop_timeout *timeout)
{
	struct client *cl = container_of(timeout, struct client, timeout);
	int sec = cl->requests > 0 ? conf.http_keepalive : conf.network_timeout;

	uh_set_client_timeout(cl, sec);
	cl->us->notify_read(cl->us, 0);
}

static void uh_poll_connection(struct client *cl)
{
	cl->timeout.cb = uh_keepalive_poll_cb;
	uloop_timeout_set(&cl->timeout, 1);
}

void uh_request_done(struct client *cl)
{
	uh_chunk_eof(cl);
	uh_dispatch_done(cl);
	blob_buf_init(&cl->hdr_response, 0);
	memset(&cl->dispatch, 0, sizeof(cl->dispatch));

	if (!conf.http_keepalive || cl->request.connection_close)
		return uh_connection_close(cl);

	cl->state = CLIENT_STATE_INIT;
	cl->requests++;
	uh_poll_connection(cl);
}

void __printf(4, 5)
uh_client_error(struct client *cl, int code, const char *summary, const char *fmt, ...)
{
	struct http_request *r = &cl->request;
	va_list arg;

	/* Close the connection even when keep alive is set, when it
	 * contains a request body, as it was not read and we are
	 * currently out of sync. Without handling this the body will be
	 * interpreted as part of the next request. The alternative
	 * would be to read and discard the request body here.
	 */
	if (r->transfer_chunked || r->content_length > 0)
		cl->request.connection_close = true;

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
	/* Signal closure to emit the correct connection headers */
	cl->request.connection_close = true;

	uh_client_error(cl, code, summary, NULL);
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
	int h_method, h_version;

	type = strtok(data, " ");
	path = strtok(NULL, " ");
	version = strtok(NULL, " ");
	if (!type || !path || !version)
		return CLIENT_STATE_DONE;

	blobmsg_add_string(&cl->hdr, "URL", path);

	memset(&cl->request, 0, sizeof(cl->request));
	h_method = find_idx(http_methods, ARRAY_SIZE(http_methods), type);
	h_version = find_idx(http_versions, ARRAY_SIZE(http_versions), version);
	if (h_method < 0 || h_version < 0) {
		req->version = UH_HTTP_VER_1_0;
		return CLIENT_STATE_DONE;
	}

	req->method = h_method;
	req->version = h_version;
	if (req->version < UH_HTTP_VER_1_1 || !conf.http_keepalive)
		req->connection_close = true;

	return CLIENT_STATE_HEADER;
}

static bool client_init_cb(struct client *cl, char *buf, int len)
{
	char *newline;

	newline = strstr(buf, "\r\n");
	if (!newline)
		return false;

	if (newline == buf) {
		ustream_consume(cl->us, 2);
		return true;
	}

	*newline = 0;
	blob_buf_init(&cl->hdr, 0);
	cl->http_code = 0;
	cl->state = client_parse_request(cl, buf);
	ustream_consume(cl->us, newline + 2 - buf);
	if (cl->state == CLIENT_STATE_DONE)
		uh_header_error(cl, 400, "Bad Request");

	return true;
}

static bool request_header_check(struct client *cl)
{
	size_t num_transfer_encoding = 0;
	size_t num_content_length = 0;
	struct blob_attr *cur;
	int rem;

	blob_for_each_attr(cur, cl->hdr.head, rem) {
		if (!strcasecmp(blobmsg_name(cur), "Transfer-Encoding"))
			num_transfer_encoding++;
		else if (!strcasecmp(blobmsg_name(cur), "Content-Length"))
			num_content_length++;
	}

	/* Section 3.3.2 of RFC 7230: messages with multiple Content-Length headers
	   containing different values MUST be rejected as invalid. Messages with
	   multiple Content-Length headers containing identical values MAY be
	   rejected as invalid */
	if (num_content_length > 1) {
		uh_header_error(cl, 400, "Bad Request");
		return false;
	}

	/* Section 3.3.3 of RFC 7230: messages with both Content-Length and
	   Transfer-Encoding ought to be handled as an error */
	if (num_content_length > 0 && num_transfer_encoding > 0) {
		uh_header_error(cl, 400, "Bad Request");
		return false;
	}

	return true;
}

static bool rfc1918_filter_check(struct client *cl)
{
	if (!conf.rfc1918_filter)
		return true;

	if (!uh_addr_rfc1918(&cl->peer_addr) || uh_addr_rfc1918(&cl->srv_addr))
		return true;

	uh_client_error(cl, 403, "Forbidden",
			"Rejected request from RFC1918 IP "
			"to public server address");
	return false;
}

static bool tls_redirect_check(struct client *cl)
{
	int rem, port;
	struct blob_attr *cur;
	char *ptr, *url = NULL, *host = NULL;

	if (cl->tls || !conf.tls_redirect)
		return true;

	if ((port = uh_first_tls_port(cl->srv_addr.family)) == -1)
		return true;

	blob_for_each_attr(cur, cl->hdr.head, rem) {
		if (!strncmp(blobmsg_name(cur), "host", 4))
			host = blobmsg_get_string(cur);

		if (!strncmp(blobmsg_name(cur), "URL", 3))
			url = blobmsg_get_string(cur);

		if (url && host)
			break;
	}

	if (!url || !host)
		return true;

	if ((ptr = strchr(host, ']')) != NULL)
		*(ptr+1) = 0;
	else if ((ptr = strchr(host, ':')) != NULL)
		*ptr = 0;

	cl->request.disable_chunked = true;
	cl->request.connection_close = true;

	uh_http_header(cl, 307, "Temporary Redirect");

	if (port != 443)
		ustream_printf(cl->us, "Location: https://%s:%d%s\r\n\r\n", host, port, url);
	else
		ustream_printf(cl->us, "Location: https://%s%s\r\n\r\n", host, url);

	uh_request_done(cl);

	return false;
}

static void client_header_complete(struct client *cl)
{
	struct http_request *r = &cl->request;

	if (!request_header_check(cl))
		return;

	if (!rfc1918_filter_check(cl))
		return;

	if (!tls_redirect_check(cl))
		return;

	if (r->expect_cont)
		ustream_printf(cl->us, "HTTP/1.1 100 Continue\r\n\r\n");

	switch(r->ua) {
	case UH_UA_MSIE_OLD:
		if (r->method != UH_HTTP_MSG_POST)
			break;

		/* fall through */
	case UH_UA_SAFARI:
		r->connection_close = true;
		break;
	default:
		break;
	}

	uh_handle_request(cl);
}

enum {
	ALPHA  = (1 << 0),
	CHAR   = (1 << 1),
	CTL    = (1 << 2),
	DIGIT  = (1 << 3),
	HEXDIG = (1 << 4),
	VCHAR  = (1 << 5),
	WSP    = (1 << 6),
	DELIM  = (1 << 7),
	VDELIM = DELIM | VCHAR,
	VALPHA = ALPHA | VCHAR,
	XALPHA = ALPHA | HEXDIG | VCHAR,
	XDIGIT = DIGIT | HEXDIG | VCHAR,
};

static uint8_t chartypes[256] = {
/* 00..07 */ CTL,    CTL,    CTL,    CTL,    CTL,    CTL,    CTL,    CTL,
/* 08..0f */ CTL,    WSP,    CTL,    CTL,    CTL,    CTL,    CTL,    CTL,
/* 10..17 */ CTL,    CTL,    CTL,    CTL,    CTL,    CTL,    CTL,    CTL,
/* 18..1f */ CTL,    CTL,    CTL,    CTL,    CTL,    CTL,    CTL,    CTL,
/* 20..27 */ WSP,    VCHAR,  VDELIM, VCHAR,  VCHAR,  VCHAR,  VCHAR,  VCHAR,
/* 28..2f */ VDELIM, VDELIM, VCHAR,  VCHAR,  VDELIM, VCHAR,  VCHAR,  VDELIM,
/* 30..37 */ XDIGIT, XDIGIT, XDIGIT, XDIGIT, XDIGIT, XDIGIT, XDIGIT, XDIGIT,
/* 38..3f */ XDIGIT, XDIGIT, VDELIM, VDELIM, VDELIM, VDELIM, VDELIM, VDELIM,
/* 40..47 */ VDELIM, XALPHA, XALPHA, XALPHA, XALPHA, XALPHA, XALPHA, VALPHA,
/* 48..4f */ VALPHA, VALPHA, VALPHA, VALPHA, VALPHA, VALPHA, VALPHA, VALPHA,
/* 50..57 */ VALPHA, VALPHA, VALPHA, VALPHA, VALPHA, VALPHA, VALPHA, VALPHA,
/* 58..5f */ VALPHA, VALPHA, VALPHA, VDELIM, VDELIM, VDELIM, VCHAR,  VCHAR,
/* 60..67 */ VCHAR,  XALPHA, XALPHA, XALPHA, XALPHA, XALPHA, XALPHA, VALPHA,
/* 68..6f */ VALPHA, VALPHA, VALPHA, VALPHA, VALPHA, VALPHA, VALPHA, VALPHA,
/* 70..77 */ VALPHA, VALPHA, VALPHA, VALPHA, VALPHA, VALPHA, VALPHA, VALPHA,
/* 78..7f */ VALPHA, VALPHA, VALPHA, VDELIM, VCHAR,  VDELIM, VCHAR,  CTL,
/* 80..ff: no flags */
};

static size_t
skip_token(char **buf, char *end)
{
	size_t len = 0;

	while (*buf < end && (chartypes[(uint8_t)**buf] & VDELIM) == VCHAR) {
		(*buf)++;
		len++;
	}

	return len;
}

static size_t
skip_qstring(char **buf, char *end)
{
	bool esc = false;
	size_t len;
	char *p;

	if (*buf + 2 >= end)
		return 0; /* need at least opening and closing quote */

	if (**buf != '"')
		return 0; /* no opening quote */

	for (p = *buf + 1, len = 1; p + 1 < end; p++, len++) {
		if (esc) {
			if (chartypes[(uint8_t)*p] & CTL)
				return 0; /* no control chars allowed */

			esc = false;
			continue;
		}

		if (*p == '"')
			break;

		if (*p == '\\') {
			esc = true;
			continue;
		}

		if (chartypes[(uint8_t)*p] & CTL)
			return 0; /* no control chars allowed */
	}

	if (esc)
		return 0; /* eof after '\' */

	if (*p != '"')
		return 0; /* unterminated string */

	*buf = p + 1;

	return len + 1;
}

static size_t
skip_whitespace(char **buf, char *end)
{
	size_t len = 0;

	while (*buf < end && (chartypes[(uint8_t)**buf] & WSP)) {
		(*buf)++;
		len++;
	}

	return len;
}

static size_t
skip_charws(char **buf, char *end, char c)
{
	size_t len = 0;
	char *p = *buf;

	while (p < end && (chartypes[(uint8_t)*p] & WSP))
		p++, len++;

	if (p == end || *p != c)
		return 0; /* expected char not present */

	*buf = p + 1;

	return len + 1;
}

static int
parse_chunksize(char *buf, char *end)
{
	int size = 0;
	char *p;

	for (p = buf; p < end; p++) {
		int n;

		if (chartypes[(uint8_t)*p] & DIGIT)
			n = *p - '0';
		else if (chartypes[(uint8_t)*p] & HEXDIG)
			n = 10 + (*p|32) - 'a';
		else
			break;

		if (size > INT_MAX / 16)
			return -1; /* overflow */

		size *= 16;

		if (size > INT_MAX - n)
			return -1; /* overflow */

		size += n;
	}

	if (p == buf)
		return -1; /* empty size */

	/* parse optional extensions */
	while (skip_charws(&p, end, ';')) {
		skip_whitespace(&p, end);

		if (!skip_token(&p, end))
			return -1; /* expected chunk-ext-name */

		if (skip_charws(&p, end, '=')) {
			skip_whitespace(&p, end);

			if (!skip_qstring(&p, end) && !skip_token(&p, end))
				return -1; /* expected chunk-ext-val */
		}
	}

	if (p < end)
		return -1; /* garbage after size and/or chunk extensions */

	return size;
}

static int
parse_contentlength(char *buf, char *end)
{
	int size = 0;
	char *p;

	for (p = buf; p < end; p++) {
		int n;

		if (chartypes[(uint8_t)*p] & DIGIT)
			n = *p - '0';
		else
			break;

		if (size > INT_MAX / 10)
			return -1; /* overflow */

		size *= 10;

		if (size > INT_MAX - n)
			return -1; /* overflow */

		size += n;
	}

	if (p == buf)
		return -1; /* empty size */

	if (p < end)
		return -1; /* garbage after size and/or chunk extensions */

	return size;
}

static void client_parse_header(struct client *cl, char *data, char *end)
{
	struct http_request *r = &cl->request;
	char *p = data;

	if (data == end) {
		uloop_timeout_cancel(&cl->timeout);
		cl->state = CLIENT_STATE_DATA;
		client_header_complete(cl);
		return;
	}

	size_t namelen = skip_token(&p, end);

	if (namelen == 0 || p == end || *p++ != ':') {
		uh_header_error(cl, 400, "Bad Request");
		return;
	}

	skip_whitespace(&p, end);

	size_t vallen = (p < end) ? end - p : 0;

	while (vallen > 0 && (chartypes[(uint8_t)p[vallen - 1]] & WSP))
		vallen--;

	if (vallen) {
		char *val = p;

		for (size_t i = 0; i < namelen; i++)
			data[i] = tolower(data[i]);

		data[namelen] = 0;
		val[vallen] = 0;

		if (!strcmp(data, "expect")) {
			if (!strcasecmp(val, "100-continue"))
				r->expect_cont = true;
			else {
				uh_header_error(cl, 412, "Precondition Failed");
				return;
			}
		} else if (!strcmp(data, "content-length")) {
			r->content_length = parse_contentlength(val, val + vallen);

			if (r->content_length < 0) {
				uh_header_error(cl, 400, "Bad Request");
				return;
			}
		} else if (!strcmp(data, "transfer-encoding")) {
			if (!strcmp(val, "chunked"))
				r->transfer_chunked = true;
		} else if (!strcmp(data, "connection")) {
			if (!strcasecmp(val, "close"))
				r->connection_close = true;
		} else if (!strcmp(data, "user-agent")) {
			char *str;

			if (strstr(val, "Opera"))
				r->ua = UH_UA_OPERA;
			else if ((str = strstr(val, "MSIE ")) != NULL) {
				r->ua = UH_UA_MSIE_NEW;
				if (str[5] && str[6] == '.') {
					switch (str[5]) {
					case '6':
						if (strstr(str, "SV1"))
							break;
						/* fall through */
					case '5':
					case '4':
						r->ua = UH_UA_MSIE_OLD;
						break;
					}
				}
			}
			else if (strstr(val, "Chrome/"))
				r->ua = UH_UA_CHROME;
			else if (strstr(val, "Safari/") && strstr(val, "Mac OS X"))
				r->ua = UH_UA_SAFARI;
			else if (strstr(val, "Gecko/"))
				r->ua = UH_UA_GECKO;
			else if (strstr(val, "Konqueror"))
				r->ua = UH_UA_KONQUEROR;
		}

		blobmsg_add_string(&cl->hdr, data, val);
	}

	cl->state = CLIENT_STATE_HEADER;
}

void client_poll_post_data(struct client *cl)
{
	struct dispatch *d = &cl->dispatch;
	struct http_request *r = &cl->request;
	enum client_state st;
	char *buf;
	int len;

	if (cl->state == CLIENT_STATE_DONE)
		return;

	while (1) {
		char *sep;
		int offset = 0;
		int cur_len;

		buf = ustream_get_read_buf(cl->us, &len);
		if (!buf || !len)
			break;

		if (!d->data_send)
			return;

		cur_len = min(r->content_length, len);
		if (cur_len) {
			if (d->data_blocked)
				break;

			if (d->data_send)
				cur_len = d->data_send(cl, buf, cur_len);

			r->content_length -= cur_len;
			ustream_consume(cl->us, cur_len);
			continue;
		}

		if (!r->transfer_chunked)
			break;

		if (r->transfer_chunked > 1)
			offset = 2;

		sep = strstr(buf + offset, "\r\n");
		if (!sep)
			break;

		r->content_length = parse_chunksize(buf + offset, sep);
		r->transfer_chunked++;
		ustream_consume(cl->us, sep + 2 - buf);

		/* invalid chunk length, abort processing and drop connection */
		if (r->content_length < 0) {
			r->content_length = 0;
			r->transfer_chunked = 0;

			/* headers already sent */
			if (cl->http_code != 0)
				uh_connection_close(cl);
			else
				uh_header_error(cl, 400, "Bad Request");

			break;
		}

		/* empty chunk == eof */
		if (!r->content_length) {
			r->transfer_chunked = false;
			break;
		}
	}

	buf = ustream_get_read_buf(cl->us, &len);
	if (!r->content_length && !r->transfer_chunked &&
		cl->state != CLIENT_STATE_DONE) {
		st = cl->state;

		if (cl->dispatch.data_done)
			cl->dispatch.data_done(cl);

		if (cl->state == st)
			cl->state = CLIENT_STATE_DONE;
	}
}

static bool client_data_cb(struct client *cl, char *buf, int len)
{
	client_poll_post_data(cl);
	return false;
}

static bool client_header_cb(struct client *cl, char *buf, int len)
{
	char *newline;
	int line_len;

	newline = strstr(buf, "\r\n");
	if (!newline)
		return false;

	client_parse_header(cl, buf, newline);
	line_len = newline + 2 - buf;
	ustream_consume(cl->us, line_len);
	if (cl->state == CLIENT_STATE_DATA)
		return client_data_cb(cl, newline + 2, len - line_len);

	return true;
}

typedef bool (*read_cb_t)(struct client *cl, char *buf, int len);
static read_cb_t read_cbs[] = {
	[CLIENT_STATE_INIT] = client_init_cb,
	[CLIENT_STATE_HEADER] = client_header_cb,
	[CLIENT_STATE_DATA] = client_data_cb,
};

void uh_client_read_cb(struct client *cl)
{
	struct ustream *us = cl->us;
	char *str;
	int len;

	client_done = false;
	do {
		str = ustream_get_read_buf(us, &len);
		if (!str || !len)
			break;

		if (cl->state >= array_size(read_cbs) || !read_cbs[cl->state])
			break;

		if (!read_cbs[cl->state](cl, str, len)) {
			if (len == us->r.buffer_len &&
			    cl->state != CLIENT_STATE_DATA &&
			    cl->state != CLIENT_STATE_DONE)
				uh_header_error(cl, 413, "Request Entity Too Large");
			break;
		}
	} while (!client_done);
}

static void client_close(struct client *cl)
{
	if (cl->refcount) {
		cl->state = CLIENT_STATE_CLEANUP;
		return;
	}

	client_done = true;
	n_clients--;
	uh_dispatch_done(cl);
	uloop_timeout_cancel(&cl->timeout);
	if (cl->tls)
		uh_tls_client_detach(cl);
	ustream_free(&cl->sfd.stream);
	close(cl->sfd.fd.fd);
	list_del(&cl->list);
	blob_buf_free(&cl->hdr);
	blob_buf_free(&cl->hdr_response);
	free(cl);

	uh_unblock_listeners();
}

void uh_client_notify_state(struct client *cl)
{
	struct ustream *s = cl->us;

	if (!s->write_error && cl->state != CLIENT_STATE_CLEANUP) {
		if (cl->state == CLIENT_STATE_DATA)
			return;

		if (!s->eof || s->w.data_bytes)
			return;

#ifdef HAVE_TLS
		if (cl->tls && cl->ssl.conn && cl->ssl.conn->w.data_bytes) {
			cl->ssl.conn->eof = s->eof;
			if (!ustream_write_pending(cl->ssl.conn))
				return;
		}
#endif
	}

	return client_close(cl);
}

static void client_ustream_read_cb(struct ustream *s, int bytes)
{
	struct client *cl = container_of(s, struct client, sfd.stream);

	uh_client_read_cb(cl);
}

static void client_ustream_write_cb(struct ustream *s, int bytes)
{
	struct client *cl = container_of(s, struct client, sfd.stream);

	if (cl->dispatch.write_cb)
		cl->dispatch.write_cb(cl);
}

static void client_notify_state(struct ustream *s)
{
	struct client *cl = container_of(s, struct client, sfd.stream);

	uh_client_notify_state(cl);
}

static void set_addr(struct uh_addr *addr, void *src)
{
	struct sockaddr_in *sin = src;
	struct sockaddr_in6 *sin6 = src;

	addr->family = sin->sin_family;
	if (addr->family == AF_INET) {
		addr->port = ntohs(sin->sin_port);
		memcpy(&addr->in, &sin->sin_addr, sizeof(addr->in));
	} else {
		addr->port = ntohs(sin6->sin6_port);
		memcpy(&addr->in6, &sin6->sin6_addr, sizeof(addr->in6));
	}
}

bool uh_accept_client(int fd, bool tls)
{
	static struct client *next_client;
	struct client *cl;
	unsigned int sl;
	int sfd;
	static int client_id = 0;
	struct sockaddr_in6 addr;

	if (!next_client)
		next_client = calloc(1, sizeof(*next_client));

	cl = next_client;

	sl = sizeof(addr);
	sfd = accept(fd, (struct sockaddr *) &addr, &sl);
	if (sfd < 0)
		return false;

	set_addr(&cl->peer_addr, &addr);
	sl = sizeof(addr);
	getsockname(sfd, (struct sockaddr *) &addr, &sl);
	set_addr(&cl->srv_addr, &addr);

	cl->us = &cl->sfd.stream;
	if (tls) {
		uh_tls_client_attach(cl);
	} else {
		cl->us->notify_read = client_ustream_read_cb;
		cl->us->notify_write = client_ustream_write_cb;
		cl->us->notify_state = client_notify_state;
	}

	cl->us->string_data = true;
	ustream_fd_init(&cl->sfd, sfd);

	uh_poll_connection(cl);
	list_add_tail(&cl->list, &clients);

	next_client = NULL;
	n_clients++;
	cl->id = client_id++;
	cl->tls = tls;

	return true;
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
