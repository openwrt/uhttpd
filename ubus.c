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
#include <libubox/blobmsg_json.h>
#include <libubox/avl.h>
#include <libubox/avl-cmp.h>
#include <stdio.h>
#include <poll.h>

#include "uhttpd.h"
#include "plugin.h"

static const struct uhttpd_ops *ops;
static struct config *_conf;
#define conf (*_conf)

static struct ubus_context *ctx;
static struct blob_buf buf;

#define UH_UBUS_MAX_POST_SIZE	65536
#define UH_UBUS_DEFAULT_SID	"00000000000000000000000000000000"

enum {
	RPC_JSONRPC,
	RPC_METHOD,
	RPC_PARAMS,
	RPC_ID,
	__RPC_MAX,
};

static const struct blobmsg_policy rpc_policy[__RPC_MAX] = {
	[RPC_JSONRPC] = { .name = "jsonrpc", .type = BLOBMSG_TYPE_STRING },
	[RPC_METHOD] = { .name = "method", .type = BLOBMSG_TYPE_STRING },
	[RPC_PARAMS] = { .name = "params", .type = BLOBMSG_TYPE_UNSPEC },
	[RPC_ID] = { .name = "id", .type = BLOBMSG_TYPE_UNSPEC },
};

enum {
	SES_ACCESS,
	__SES_MAX,
};

static const struct blobmsg_policy ses_policy[__SES_MAX] = {
	[SES_ACCESS] = { .name = "access", .type = BLOBMSG_TYPE_BOOL },
};

struct rpc_data {
	struct blob_attr *id;
	const char *sid;
	const char *method;
	const char *object;
	const char *function;
	struct blob_attr *data;
	struct blob_attr *params;
};

struct list_data {
	bool verbose;
	bool add_object;
	struct blob_buf *buf;
};

enum rpc_error {
	ERROR_PARSE,
	ERROR_REQUEST,
	ERROR_METHOD,
	ERROR_PARAMS,
	ERROR_INTERNAL,
	ERROR_OBJECT,
	ERROR_SESSION,
	ERROR_ACCESS,
	ERROR_TIMEOUT,
	__ERROR_MAX
};

static const struct {
	int code;
	const char *msg;
} json_errors[__ERROR_MAX] = {
	[ERROR_PARSE] = { -32700, "Parse error" },
	[ERROR_REQUEST] = { -32600, "Invalid request" },
	[ERROR_METHOD] = { -32601, "Method not found" },
	[ERROR_PARAMS] = { -32602, "Invalid parameters" },
	[ERROR_INTERNAL] = { -32603, "Internal error" },
	[ERROR_OBJECT] = { -32000, "Object not found" },
	[ERROR_SESSION] = { -32001, "Session not found" },
	[ERROR_ACCESS] = { -32002, "Access denied" },
	[ERROR_TIMEOUT] = { -32003, "ubus request timed out" },
};

enum cors_hdr {
	HDR_ORIGIN,
	HDR_ACCESS_CONTROL_REQUEST_METHOD,
	HDR_ACCESS_CONTROL_REQUEST_HEADERS,
	__HDR_MAX
};

enum ubus_hdr {
	HDR_AUTHORIZATION,
	__HDR_UBUS_MAX
};

static const char *uh_ubus_get_auth(const struct blob_attr *attr)
{
	static const struct blobmsg_policy hdr_policy[__HDR_UBUS_MAX] = {
		[HDR_AUTHORIZATION] = { "authorization", BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *tb[__HDR_UBUS_MAX];

	blobmsg_parse(hdr_policy, __HDR_UBUS_MAX, tb, blob_data(attr), blob_len(attr));

	if (tb[HDR_AUTHORIZATION]) {
		const char *tmp = blobmsg_get_string(tb[HDR_AUTHORIZATION]);

		if (!strncasecmp(tmp, "Bearer ", 7))
			return tmp + 7;
	}

	return UH_UBUS_DEFAULT_SID;
}

static void __uh_ubus_next_batched_request(struct uloop_timeout *timeout);

static void uh_ubus_next_batched_request(struct client *cl)
{
	struct dispatch_ubus *du = &cl->dispatch.ubus;

	du->timeout.cb = __uh_ubus_next_batched_request;
	uloop_timeout_set(&du->timeout, 1);
}

static void uh_ubus_add_cors_headers(struct client *cl)
{
	struct blob_attr *tb[__HDR_MAX];
	static const struct blobmsg_policy hdr_policy[__HDR_MAX] = {
		[HDR_ORIGIN] = { "origin", BLOBMSG_TYPE_STRING },
		[HDR_ACCESS_CONTROL_REQUEST_METHOD] = { "access-control-request-method", BLOBMSG_TYPE_STRING },
		[HDR_ACCESS_CONTROL_REQUEST_HEADERS] = { "access-control-request-headers", BLOBMSG_TYPE_STRING },
	};

	blobmsg_parse(hdr_policy, __HDR_MAX, tb, blob_data(cl->hdr.head), blob_len(cl->hdr.head));

	if (!tb[HDR_ORIGIN])
		return;

	if (tb[HDR_ACCESS_CONTROL_REQUEST_METHOD])
	{
		char *hdr = (char *) blobmsg_data(tb[HDR_ACCESS_CONTROL_REQUEST_METHOD]);

		if (strcmp(hdr, "GET") && strcmp(hdr, "POST") && strcmp(hdr, "OPTIONS"))
			return;
	}

	ustream_printf(cl->us, "Access-Control-Allow-Origin: %s\r\n",
	               blobmsg_get_string(tb[HDR_ORIGIN]));

	if (tb[HDR_ACCESS_CONTROL_REQUEST_HEADERS])
		ustream_printf(cl->us, "Access-Control-Allow-Headers: %s\r\n",
		               blobmsg_get_string(tb[HDR_ACCESS_CONTROL_REQUEST_HEADERS]));

	ustream_printf(cl->us, "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n");
	ustream_printf(cl->us, "Access-Control-Allow-Credentials: true\r\n");
}

static void uh_ubus_send_header(struct client *cl, int code, const char *summary, const char *content_type)
{
	ops->http_header(cl, code, summary);

	if (conf.ubus_cors)
		uh_ubus_add_cors_headers(cl);

	ustream_printf(cl->us, "Content-Type: %s\r\n", content_type);

	if (cl->request.method == UH_HTTP_MSG_OPTIONS)
		ustream_printf(cl->us, "Content-Length: 0\r\n");

	ustream_printf(cl->us, "\r\n");
}

static void uh_ubus_send_response(struct client *cl, struct blob_buf *buf)
{
	struct dispatch_ubus *du = &cl->dispatch.ubus;
	const char *sep = "";
	char *str;

	if (du->array && du->array_idx > 1)
		sep = ",";

	str = blobmsg_format_json(buf->head, true);
	ops->chunk_printf(cl, "%s%s", sep, str);
	free(str);

	du->jsobj_cur = NULL;
	if (du->array)
		uh_ubus_next_batched_request(cl);
	else
		return ops->request_done(cl);
}

static void uh_ubus_init_json_rpc_response(struct client *cl, struct blob_buf *buf)
{
	struct dispatch_ubus *du = &cl->dispatch.ubus;
	struct json_object *obj = du->jsobj_cur, *obj2 = NULL;

	blobmsg_add_string(buf, "jsonrpc", "2.0");

	if (obj)
		json_object_object_get_ex(obj, "id", &obj2);

	if (obj2)
		blobmsg_add_json_element(buf, "id", obj2);
	else
		blobmsg_add_field(buf, BLOBMSG_TYPE_UNSPEC, "id", NULL, 0);
}

static void uh_ubus_json_rpc_error(struct client *cl, enum rpc_error type)
{
	void *c;

	blob_buf_init(&buf, 0);

	uh_ubus_init_json_rpc_response(cl, &buf);
	c = blobmsg_open_table(&buf, "error");
	blobmsg_add_u32(&buf, "code", json_errors[type].code);
	blobmsg_add_string(&buf, "message", json_errors[type].msg);
	blobmsg_close_table(&buf, c);
	uh_ubus_send_response(cl, &buf);
}

static void uh_ubus_error(struct client *cl, int code, const char *message)
{
	blob_buf_init(&buf, 0);

	blobmsg_add_u32(&buf, "code", code);
	blobmsg_add_string(&buf, "message", message);
	uh_ubus_send_response(cl, &buf);
}

static void uh_ubus_posix_error(struct client *cl, int err)
{
	uh_ubus_error(cl, -err, strerror(err));
}

static void uh_ubus_ubus_error(struct client *cl, int err)
{
	uh_ubus_error(cl, err, ubus_strerror(err));
}

static void uh_ubus_allowed_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr *tb[__SES_MAX];
	bool *allow = (bool *)req->priv;

	if (!msg)
		return;

	blobmsg_parse(ses_policy, __SES_MAX, tb, blob_data(msg), blob_len(msg));

	if (tb[SES_ACCESS])
		*allow = blobmsg_get_bool(tb[SES_ACCESS]);
}

static bool uh_ubus_allowed(const char *sid, const char *obj, const char *fun)
{
	uint32_t id;
	bool allow = false;
	static struct blob_buf req;

	if (ubus_lookup_id(ctx, "session", &id))
		return false;

	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "ubus_rpc_session", sid);
	blobmsg_add_string(&req, "object", obj);
	blobmsg_add_string(&req, "function", fun);

	ubus_invoke(ctx, id, "access", req.head, uh_ubus_allowed_cb, &allow, conf.script_timeout * 500);

	return allow;
}

/* GET requests handling */

static void uh_ubus_list_cb(struct ubus_context *ctx, struct ubus_object_data *obj, void *priv);

static void uh_ubus_handle_get_list(struct client *cl, const char *path)
{
	static struct blob_buf tmp;
	struct list_data data = { .verbose = true, .add_object = !path, .buf = &tmp};
	struct blob_attr *cur;
	int rem;
	int err;

	blob_buf_init(&tmp, 0);

	err = ubus_lookup(ctx, path, uh_ubus_list_cb, &data);
	if (err) {
		uh_ubus_send_header(cl, 500, "Ubus Protocol Error", "application/json");
		uh_ubus_ubus_error(cl, err);
		return;
	}

	blob_buf_init(&buf, 0);
	blob_for_each_attr(cur, tmp.head, rem)
		blobmsg_add_blob(&buf, cur);

	uh_ubus_send_header(cl, 200, "OK", "application/json");
	uh_ubus_send_response(cl, &buf);
}

static int uh_ubus_subscription_notification_cb(struct ubus_context *ctx,
						struct ubus_object *obj,
						struct ubus_request_data *req,
						const char *method,
						struct blob_attr *msg)
{
	struct ubus_subscriber *s;
	struct dispatch_ubus *du;
	struct client *cl;
	char *json;

	s = container_of(obj, struct ubus_subscriber, obj);
	du = container_of(s, struct dispatch_ubus, sub);
	cl = container_of(du, struct client, dispatch.ubus);

	json = blobmsg_format_json(msg, true);
	if (json) {
		ops->chunk_printf(cl, "event: %s\ndata: %s\n\n", method, json);
		free(json);
	}

	return 0;
}

static void uh_ubus_subscription_notification_remove_cb(struct ubus_context *ctx, struct ubus_subscriber *s, uint32_t id)
{
	struct dispatch_ubus *du;
	struct client *cl;

	du = container_of(s, struct dispatch_ubus, sub);
	cl = container_of(du, struct client, dispatch.ubus);

	ubus_unregister_subscriber(ctx, &du->sub);

	ops->request_done(cl);
}

static void uh_ubus_handle_get_subscribe(struct client *cl, const char *path)
{
	struct dispatch_ubus *du = &cl->dispatch.ubus;
	const char *sid;
	uint32_t id;
	int err;

	sid = uh_ubus_get_auth(cl->hdr.head);

	if (!conf.ubus_noauth && !uh_ubus_allowed(sid, path, ":subscribe")) {
		uh_ubus_send_header(cl, 200, "OK", "application/json");
		uh_ubus_posix_error(cl, EACCES);
		return;
	}

	du->sub.cb = uh_ubus_subscription_notification_cb;
	du->sub.remove_cb = uh_ubus_subscription_notification_remove_cb;

	uh_client_ref(cl);

	err = ubus_register_subscriber(ctx, &du->sub);
	if (err)
		goto err_unref;

	err = ubus_lookup_id(ctx, path, &id);
	if (err)
		goto err_unregister;

	err = ubus_subscribe(ctx, &du->sub, id);
	if (err)
		goto err_unregister;

	uh_ubus_send_header(cl, 200, "OK", "text/event-stream");

	if (conf.events_retry)
		ops->chunk_printf(cl, "retry: %d\n", conf.events_retry);

	return;

err_unregister:
	ubus_unregister_subscriber(ctx, &du->sub);
err_unref:
	uh_client_unref(cl);
	if (err) {
		uh_ubus_send_header(cl, 200, "OK", "application/json");
		uh_ubus_ubus_error(cl, err);
	}
}

static void uh_ubus_handle_get(struct client *cl)
{
	struct dispatch_ubus *du = &cl->dispatch.ubus;
	const char *url = du->url_path;

	url += strlen(conf.ubus_prefix);

	if (!strcmp(url, "/list") || !strncmp(url, "/list/", strlen("/list/"))) {
		url += strlen("/list");

		uh_ubus_handle_get_list(cl, *url ? url + 1 : NULL);
	} else if (!strncmp(url, "/subscribe/", strlen("/subscribe/"))) {
		url += strlen("/subscribe");

		uh_ubus_handle_get_subscribe(cl, url + 1);
	} else {
		ops->http_header(cl, 404, "Not Found");
		ustream_printf(cl->us, "\r\n");
		ops->request_done(cl);
	}
}

/* POST requests handling */

static void
uh_ubus_request_data_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct dispatch_ubus *du = container_of(req, struct dispatch_ubus, req);
	struct blob_attr *cur;
	int len;

	blob_for_each_attr(cur, msg, len)
		blobmsg_add_blob(&du->buf, cur);
}

static void
uh_ubus_request_cb(struct ubus_request *req, int ret)
{
	struct dispatch_ubus *du = container_of(req, struct dispatch_ubus, req);
	struct client *cl = container_of(du, struct client, dispatch.ubus);
	struct blob_attr *cur;
	void *r;
	int rem;

	blob_buf_init(&buf, 0);

	uloop_timeout_cancel(&du->timeout);

	/* Legacy format always uses "result" array - even for errors and empty
	 * results. */
	if (du->legacy) {
		void *c;

		uh_ubus_init_json_rpc_response(cl, &buf);
		r = blobmsg_open_array(&buf, "result");
		blobmsg_add_u32(&buf, "", ret);

		if (blob_len(du->buf.head)) {
			c = blobmsg_open_table(&buf, NULL);
			blob_for_each_attr(cur, du->buf.head, rem)
				blobmsg_add_blob(&buf, cur);
			blobmsg_close_table(&buf, c);
		}

		blobmsg_close_array(&buf, r);
		uh_ubus_send_response(cl, &buf);
		return;
	}

	if (ret) {
		void *c;

		uh_ubus_init_json_rpc_response(cl, &buf);
		c = blobmsg_open_table(&buf, "error");
		blobmsg_add_u32(&buf, "code", ret);
		blobmsg_add_string(&buf, "message", ubus_strerror(ret));
		blobmsg_close_table(&buf, c);
		uh_ubus_send_response(cl, &buf);
	} else {
		uh_ubus_init_json_rpc_response(cl, &buf);
		if (blob_len(du->buf.head)) {
			r = blobmsg_open_table(&buf, "result");
			blob_for_each_attr(cur, du->buf.head, rem)
				blobmsg_add_blob(&buf, cur);
			blobmsg_close_table(&buf, r);
		} else {
			blobmsg_add_field(&buf, BLOBMSG_TYPE_UNSPEC, "result", NULL, 0);
		}
		uh_ubus_send_response(cl, &buf);
	}

}

static void
uh_ubus_timeout_cb(struct uloop_timeout *timeout)
{
	struct dispatch_ubus *du = container_of(timeout, struct dispatch_ubus, timeout);
	struct client *cl = container_of(du, struct client, dispatch.ubus);

	ubus_abort_request(ctx, &du->req);
	uh_ubus_json_rpc_error(cl, ERROR_TIMEOUT);
}

static void uh_ubus_close_fds(struct client *cl)
{
	if (ctx->sock.fd < 0)
		return;

	close(ctx->sock.fd);
	ctx->sock.fd = -1;
}

static void uh_ubus_request_free(struct client *cl)
{
	struct dispatch_ubus *du = &cl->dispatch.ubus;

	blob_buf_free(&du->buf);
	uloop_timeout_cancel(&du->timeout);

	if (du->jsobj)
		json_object_put(du->jsobj);

	if (du->jstok)
		json_tokener_free(du->jstok);

	if (du->req_pending)
		ubus_abort_request(ctx, &du->req);

	free(du->url_path);
	du->url_path = NULL;
}

static void uh_ubus_single_error(struct client *cl, enum rpc_error type)
{
	uh_ubus_send_header(cl, 200, "OK", "application/json");
	uh_ubus_json_rpc_error(cl, type);
	ops->request_done(cl);
}

static void uh_ubus_send_request(struct client *cl, const char *sid, struct blob_attr *args)
{
	struct dispatch *d = &cl->dispatch;
	struct dispatch_ubus *du = &d->ubus;
	struct blob_attr *cur;
	static struct blob_buf req;
	int ret, rem;

	blob_buf_init(&req, 0);
	blobmsg_for_each_attr(cur, args, rem) {
		if (!strcmp(blobmsg_name(cur), "ubus_rpc_session"))
			return uh_ubus_json_rpc_error(cl, ERROR_PARAMS);
		blobmsg_add_blob(&req, cur);
	}

	blobmsg_add_string(&req, "ubus_rpc_session", sid);

	blob_buf_init(&du->buf, 0);
	memset(&du->req, 0, sizeof(du->req));
	ret = ubus_invoke_async(ctx, du->obj, du->func, req.head, &du->req);
	if (ret)
		return uh_ubus_json_rpc_error(cl, ERROR_INTERNAL);

	du->req.data_cb = uh_ubus_request_data_cb;
	du->req.complete_cb = uh_ubus_request_cb;
	ubus_complete_request_async(ctx, &du->req);

	du->timeout.cb = uh_ubus_timeout_cb;
	uloop_timeout_set(&du->timeout, conf.script_timeout * 1000);

	du->req_pending = true;
}

static void uh_ubus_list_cb(struct ubus_context *ctx, struct ubus_object_data *obj, void *priv)
{
	struct blob_attr *sig, *attr;
	struct list_data *data = priv;
	int rem, rem2;
	void *t, *o;

	if (!data->verbose) {
		blobmsg_add_string(data->buf, NULL, obj->path);
		return;
	}

	if (!obj->signature)
		return;

	if (data->add_object)
		o = blobmsg_open_table(data->buf, obj->path);
	blob_for_each_attr(sig, obj->signature, rem) {
		t = blobmsg_open_table(data->buf, blobmsg_name(sig));
		rem2 = blobmsg_data_len(sig);
		__blob_for_each_attr(attr, blobmsg_data(sig), rem2) {
			if (blob_id(attr) != BLOBMSG_TYPE_INT32)
				continue;

			switch (blobmsg_get_u32(attr)) {
			case BLOBMSG_TYPE_INT8:
				blobmsg_add_string(data->buf, blobmsg_name(attr), "boolean");
				break;
			case BLOBMSG_TYPE_INT32:
				blobmsg_add_string(data->buf, blobmsg_name(attr), "number");
				break;
			case BLOBMSG_TYPE_STRING:
				blobmsg_add_string(data->buf, blobmsg_name(attr), "string");
				break;
			case BLOBMSG_TYPE_ARRAY:
				blobmsg_add_string(data->buf, blobmsg_name(attr), "array");
				break;
			case BLOBMSG_TYPE_TABLE:
				blobmsg_add_string(data->buf, blobmsg_name(attr), "object");
				break;
			default:
				blobmsg_add_string(data->buf, blobmsg_name(attr), "unknown");
				break;
			}
		}
		blobmsg_close_table(data->buf, t);
	}
	if (data->add_object)
		blobmsg_close_table(data->buf, o);
}

static void uh_ubus_send_list(struct client *cl, struct blob_attr *params)
{
	struct blob_attr *cur, *dup;
	struct list_data data = { .buf = &cl->dispatch.ubus.buf, .verbose = false, .add_object = true };
	void *r;
	int rem;

	blob_buf_init(data.buf, 0);

	uh_client_ref(cl);

	if (!params || blob_id(params) != BLOBMSG_TYPE_ARRAY) {
		r = blobmsg_open_array(data.buf, "result");
		ubus_lookup(ctx, NULL, uh_ubus_list_cb, &data);
		blobmsg_close_array(data.buf, r);
	}
	else {
		r = blobmsg_open_table(data.buf, "result");
		dup = blob_memdup(params);
		if (dup)
		{
			rem = blobmsg_data_len(dup);
			data.verbose = true;
			__blob_for_each_attr(cur, blobmsg_data(dup), rem)
				ubus_lookup(ctx, blobmsg_data(cur), uh_ubus_list_cb, &data);
			free(dup);
		}
		blobmsg_close_table(data.buf, r);
	}

	uh_client_unref(cl);

	blob_buf_init(&buf, 0);
	uh_ubus_init_json_rpc_response(cl, &buf);
	blobmsg_add_blob(&buf, blob_data(data.buf->head));
	uh_ubus_send_response(cl, &buf);
}

static bool parse_json_rpc(struct rpc_data *d, struct blob_attr *data)
{
	struct blob_attr *tb[__RPC_MAX];
	struct blob_attr *cur;

	blobmsg_parse(rpc_policy, __RPC_MAX, tb, blob_data(data), blob_len(data));

	cur = tb[RPC_JSONRPC];
	if (!cur || strcmp(blobmsg_data(cur), "2.0") != 0)
		return false;

	cur = tb[RPC_METHOD];
	if (!cur)
		return false;

	d->id = tb[RPC_ID];
	d->method = blobmsg_data(cur);

	cur = tb[RPC_PARAMS];
	if (!cur)
		return true;

	d->params = blob_memdup(cur);
	if (!d->params)
		return false;

	return true;
}

static void parse_call_params(struct rpc_data *d)
{
	const struct blobmsg_policy data_policy[] = {
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_TABLE },
	};
	struct blob_attr *tb[4];

	if (!d->params || blobmsg_type(d->params) != BLOBMSG_TYPE_ARRAY)
		return;

	blobmsg_parse_array(data_policy, ARRAY_SIZE(data_policy), tb,
			    blobmsg_data(d->params), blobmsg_data_len(d->params));

	if (tb[0])
		d->sid = blobmsg_data(tb[0]);

	if (conf.ubus_noauth && (!d->sid || !*d->sid))
		d->sid = UH_UBUS_DEFAULT_SID;

	if (tb[1])
		d->object = blobmsg_data(tb[1]);

	if (tb[2])
		d->function = blobmsg_data(tb[2]);

	d->data = tb[3];
}

static void uh_ubus_init_batch(struct client *cl)
{
	struct dispatch_ubus *du = &cl->dispatch.ubus;

	du->array = true;
	uh_ubus_send_header(cl, 200, "OK", "application/json");
	ops->chunk_printf(cl, "[");
}

static void uh_ubus_complete_batch(struct client *cl)
{
	ops->chunk_printf(cl, "]");
	ops->request_done(cl);
}

static void uh_ubus_handle_request_object(struct client *cl, struct json_object *obj)
{
	struct dispatch_ubus *du = &cl->dispatch.ubus;
	struct rpc_data data = {};
	enum rpc_error err = ERROR_PARSE;
	static struct blob_buf req;

	uh_client_ref(cl);

	if (json_object_get_type(obj) != json_type_object)
		goto error;

	du->jsobj_cur = obj;
	blob_buf_init(&req, 0);
	if (!blobmsg_add_object(&req, obj))
		goto error;

	if (!parse_json_rpc(&data, req.head))
		goto error;

	if (!strcmp(data.method, "call")) {
		parse_call_params(&data);

		if (!data.sid || !data.object || !data.function || !data.data)
			goto error;

		du->func = data.function;
		if (ubus_lookup_id(ctx, data.object, &du->obj)) {
			err = ERROR_OBJECT;
			goto error;
		}

		if (!conf.ubus_noauth && !uh_ubus_allowed(data.sid, data.object, data.function)) {
			err = ERROR_ACCESS;
			goto error;
		}

		uh_ubus_send_request(cl, data.sid, data.data);
		goto out;
	}
	else if (!strcmp(data.method, "list")) {
		uh_ubus_send_list(cl, data.params);
		goto out;
	}
	else {
		err = ERROR_METHOD;
		goto error;
	}

error:
	uh_ubus_json_rpc_error(cl, err);
out:
	if (data.params)
		free(data.params);

	uh_client_unref(cl);
}

static void __uh_ubus_next_batched_request(struct uloop_timeout *timeout)
{
	struct dispatch_ubus *du = container_of(timeout, struct dispatch_ubus, timeout);
	struct client *cl = container_of(du, struct client, dispatch.ubus);
	struct json_object *obj = du->jsobj;
	int len;

	len = json_object_array_length(obj);
	if (du->array_idx >= len)
		return uh_ubus_complete_batch(cl);

	obj = json_object_array_get_idx(obj, du->array_idx++);
	uh_ubus_handle_request_object(cl, obj);
}

static void uh_ubus_data_done(struct client *cl)
{
	struct dispatch_ubus *du = &cl->dispatch.ubus;
	struct json_object *obj = du->jsobj;

	switch (obj ? json_object_get_type(obj) : json_type_null) {
	case json_type_object:
		uh_ubus_send_header(cl, 200, "OK", "application/json");
		return uh_ubus_handle_request_object(cl, obj);
	case json_type_array:
		uh_ubus_init_batch(cl);
		return uh_ubus_next_batched_request(cl);
	default:
		return uh_ubus_single_error(cl, ERROR_PARSE);
	}
}

static void uh_ubus_call(struct client *cl, const char *path, const char *sid)
{
	struct dispatch_ubus *du = &cl->dispatch.ubus;
	struct json_object *obj = du->jsobj;
	struct rpc_data data = {};
	enum rpc_error err = ERROR_PARSE;
	static struct blob_buf req;

	uh_client_ref(cl);

	if (!obj || json_object_get_type(obj) != json_type_object)
		goto error;

	uh_ubus_send_header(cl, 200, "OK", "application/json");

	du->jsobj_cur = obj;
	blob_buf_init(&req, 0);
	if (!blobmsg_add_object(&req, obj))
		goto error;

	if (!parse_json_rpc(&data, req.head))
		goto error;

	du->func = data.method;
	if (ubus_lookup_id(ctx, path, &du->obj)) {
		err = ERROR_OBJECT;
		goto error;
	}

	if (!conf.ubus_noauth && !uh_ubus_allowed(sid, path, data.method)) {
		err = ERROR_ACCESS;
		goto error;
	}

	uh_ubus_send_request(cl, sid, data.params);
	goto out;

error:
	uh_ubus_json_rpc_error(cl, err);
out:
	if (data.params)
		free(data.params);

	uh_client_unref(cl);
}

static void uh_ubus_handle_post(struct client *cl)
{
	struct dispatch_ubus *du = &cl->dispatch.ubus;
	const char *url = du->url_path;
	const char *auth;

	/* Treat both: /foo AND /foo/ as legacy requests. */
	if (ops->path_match(conf.ubus_prefix, url) && strlen(url) - strlen(conf.ubus_prefix) <= 1) {
		du->legacy = true;
		uh_ubus_data_done(cl);
		return;
	}

	auth = uh_ubus_get_auth(cl->hdr.head);

	url += strlen(conf.ubus_prefix);

	if (!strncmp(url, "/call/", strlen("/call/"))) {
		url += strlen("/call/");

		uh_ubus_call(cl, url, auth);
	} else {
		ops->http_header(cl, 404, "Not Found");
		ustream_printf(cl->us, "\r\n");
		ops->request_done(cl);
	}
}

static int uh_ubus_data_send(struct client *cl, const char *data, int len)
{
	struct dispatch_ubus *du = &cl->dispatch.ubus;

	if (du->jsobj || !du->jstok)
		goto error;

	du->post_len += len;
	if (du->post_len > UH_UBUS_MAX_POST_SIZE)
		goto error;

	du->jsobj = json_tokener_parse_ex(du->jstok, data, len);
	return len;

error:
	uh_ubus_single_error(cl, ERROR_PARSE);
	return 0;
}

static void uh_ubus_handle_request(struct client *cl, char *url, struct path_info *pi)
{
	struct dispatch *d = &cl->dispatch;
	struct dispatch_ubus *du = &d->ubus;
	char *chr;

	du->url_path = strdup(url);
	if (!du->url_path) {
		ops->client_error(cl, 500, "Internal Server Error", "Failed to allocate resources");
		return;
	}
	chr = strchr(du->url_path, '?');
	if (chr)
		chr[0] = '\0';

	du->legacy = false;

	switch (cl->request.method)
	{
	case UH_HTTP_MSG_GET:
		uh_ubus_handle_get(cl);
		break;
	case UH_HTTP_MSG_POST:
		d->data_send = uh_ubus_data_send;
		d->data_done = uh_ubus_handle_post;
		d->close_fds = uh_ubus_close_fds;
		d->free = uh_ubus_request_free;
		du->jstok = json_tokener_new();
		return;

	case UH_HTTP_MSG_OPTIONS:
		uh_ubus_send_header(cl, 200, "OK", "application/json");
		ops->request_done(cl);
		break;

	default:
		ops->client_error(cl, 400, "Bad Request", "Invalid Request");
	}

	free(du->url_path);
	du->url_path = NULL;
}

static bool
uh_ubus_check_url(const char *url)
{
	return ops->path_match(conf.ubus_prefix, url);
}

static int
uh_ubus_init(void)
{
	static struct dispatch_handler ubus_dispatch = {
		.check_url = uh_ubus_check_url,
		.handle_request = uh_ubus_handle_request,
	};

	ctx = ubus_connect(conf.ubus_socket);
	if (!ctx) {
		fprintf(stderr, "Unable to connect to ubus socket\n");
		exit(1);
	}

	ops->dispatch_add(&ubus_dispatch);

	uloop_done();
	return 0;
}


static int uh_ubus_plugin_init(const struct uhttpd_ops *o, struct config *c)
{
	ops = o;
	_conf = c;
	return uh_ubus_init();
}

static void uh_ubus_post_init(void)
{
	ubus_add_uloop(ctx);
}

struct uhttpd_plugin uhttpd_plugin = {
	.init = uh_ubus_plugin_init,
	.post_init = uh_ubus_post_init,
};
