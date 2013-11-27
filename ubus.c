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

#define UH_UBUS_MAX_POST_SIZE	4096
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
	[RPC_PARAMS] = { .name = "params", .type = BLOBMSG_TYPE_ARRAY },
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

static void __uh_ubus_next_batched_request(struct uloop_timeout *timeout);

static void uh_ubus_next_batched_request(struct client *cl)
{
	struct dispatch_ubus *du = &cl->dispatch.ubus;

	du->timeout.cb = __uh_ubus_next_batched_request;
	uloop_timeout_set(&du->timeout, 1);
}

static void uh_ubus_send_header(struct client *cl)
{
	ops->http_header(cl, 200, "OK");
	ustream_printf(cl->us, "Content-Type: application/json\r\n\r\n");
}

static void uh_ubus_send_response(struct client *cl)
{
	struct dispatch_ubus *du = &cl->dispatch.ubus;
	const char *sep = "";
	char *str;

	if (du->array && du->array_idx > 1)
		sep = ",";

	str = blobmsg_format_json(buf.head, true);
	ops->chunk_printf(cl, "%s%s", sep, str);
	free(str);

	du->jsobj_cur = NULL;
	if (du->array)
		uh_ubus_next_batched_request(cl);
	else
		return ops->request_done(cl);
}

static void uh_ubus_init_response(struct client *cl)
{
	struct dispatch_ubus *du = &cl->dispatch.ubus;
	struct json_object *obj = du->jsobj_cur;

	blob_buf_init(&buf, 0);
	blobmsg_add_string(&buf, "jsonrpc", "2.0");

	if (obj)
		obj = json_object_object_get(obj, "id");

	if (obj)
		blobmsg_add_json_element(&buf, "id", obj);
	else
		blobmsg_add_field(&buf, BLOBMSG_TYPE_UNSPEC, "id", NULL, 0);
}

static void uh_ubus_json_error(struct client *cl, enum rpc_error type)
{
	void *c;

	uh_ubus_init_response(cl);
	c = blobmsg_open_table(&buf, "error");
	blobmsg_add_u32(&buf, "code", json_errors[type].code);
	blobmsg_add_string(&buf, "message", json_errors[type].msg);
	blobmsg_close_table(&buf, c);
	uh_ubus_send_response(cl);
}

static void
uh_ubus_request_data_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct dispatch_ubus *du = container_of(req, struct dispatch_ubus, req);

	blobmsg_add_field(&du->buf, BLOBMSG_TYPE_TABLE, "", blob_data(msg), blob_len(msg));
}

static void
uh_ubus_request_cb(struct ubus_request *req, int ret)
{
	struct dispatch_ubus *du = container_of(req, struct dispatch_ubus, req);
	struct client *cl = container_of(du, struct client, dispatch.ubus);
	struct blob_attr *cur;
	void *r;
	int rem;

	uloop_timeout_cancel(&du->timeout);
	uh_ubus_init_response(cl);
	r = blobmsg_open_array(&buf, "result");
	blobmsg_add_u32(&buf, "", ret);
	blob_for_each_attr(cur, du->buf.head, rem)
		blobmsg_add_blob(&buf, cur);
	blobmsg_close_array(&buf, r);
	uh_ubus_send_response(cl);
}

static void
uh_ubus_timeout_cb(struct uloop_timeout *timeout)
{
	struct dispatch_ubus *du = container_of(timeout, struct dispatch_ubus, timeout);
	struct client *cl = container_of(du, struct client, dispatch.ubus);

	ubus_abort_request(ctx, &du->req);
	uh_ubus_json_error(cl, ERROR_TIMEOUT);
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
}

static void uh_ubus_single_error(struct client *cl, enum rpc_error type)
{
	uh_ubus_send_header(cl);
	uh_ubus_json_error(cl, type);
	ops->request_done(cl);
}

static void uh_ubus_send_request(struct client *cl, json_object *obj, const char *sid, struct blob_attr *args)
{
	struct dispatch *d = &cl->dispatch;
	struct dispatch_ubus *du = &d->ubus;
	struct blob_attr *cur;
	static struct blob_buf req;
	int ret, rem;

	blob_buf_init(&req, 0);
	blobmsg_for_each_attr(cur, args, rem) {
		if (!strcmp(blobmsg_name(cur), "ubus_rpc_session"))
			return uh_ubus_json_error(cl, ERROR_PARAMS);
		blobmsg_add_blob(&req, cur);
	}

	blobmsg_add_string(&req, "ubus_rpc_session", sid);

	blob_buf_init(&du->buf, 0);
	memset(&du->req, 0, sizeof(du->req));
	ret = ubus_invoke_async(ctx, du->obj, du->func, req.head, &du->req);
	if (ret)
		return uh_ubus_json_error(cl, ERROR_INTERNAL);

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
	blobmsg_close_table(data->buf, o);
}

static void uh_ubus_send_list(struct client *cl, json_object *obj, struct blob_attr *params)
{
	struct blob_attr *cur, *dup;
	struct list_data data = { .buf = &cl->dispatch.ubus.buf, .verbose = false };
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

	uh_ubus_init_response(cl);
	blobmsg_add_blob(&buf, blob_data(data.buf->head));
	uh_ubus_send_response(cl);
}

static bool parse_json_rpc(struct rpc_data *d, struct blob_attr *data)
{
	const struct blobmsg_policy data_policy[] = {
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_TABLE },
	};
	struct blob_attr *tb[__RPC_MAX];
	struct blob_attr *tb2[4];
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

	blobmsg_parse_array(data_policy, ARRAY_SIZE(data_policy), tb2,
			    blobmsg_data(d->params), blobmsg_data_len(d->params));

	if (tb2[0])
		d->sid = blobmsg_data(tb2[0]);

	if (conf.ubus_noauth && (!d->sid || !*d->sid))
		d->sid = UH_UBUS_DEFAULT_SID;

	if (tb2[1])
		d->object = blobmsg_data(tb2[1]);

	if (tb2[2])
		d->function = blobmsg_data(tb2[2]);

	d->data = tb2[3];

	return true;
}

static void uh_ubus_init_batch(struct client *cl)
{
	struct dispatch_ubus *du = &cl->dispatch.ubus;

	du->array = true;
	uh_ubus_send_header(cl);
	ops->chunk_printf(cl, "[");
}

static void uh_ubus_complete_batch(struct client *cl)
{
	ops->chunk_printf(cl, "]");
	ops->request_done(cl);
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

static void uh_ubus_handle_request_object(struct client *cl, struct json_object *obj)
{
	struct dispatch_ubus *du = &cl->dispatch.ubus;
	struct rpc_data data = {};
	enum rpc_error err = ERROR_PARSE;

	uh_client_ref(cl);

	if (json_object_get_type(obj) != json_type_object)
		goto error;

	du->jsobj_cur = obj;
	blob_buf_init(&buf, 0);
	if (!blobmsg_add_object(&buf, obj))
		goto error;

	if (!parse_json_rpc(&data, buf.head))
		goto error;

	if (!strcmp(data.method, "call")) {
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

		uh_ubus_send_request(cl, obj, data.sid, data.data);
		goto out;
	}
	else if (!strcmp(data.method, "list")) {
		uh_ubus_send_list(cl, obj, data.params);
		goto out;
	}
	else {
		err = ERROR_METHOD;
		goto error;
	}

error:
	uh_ubus_json_error(cl, err);
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
		uh_ubus_send_header(cl);
		return uh_ubus_handle_request_object(cl, obj);
	case json_type_array:
		uh_ubus_init_batch(cl);
		return uh_ubus_next_batched_request(cl);
	default:
		return uh_ubus_single_error(cl, ERROR_PARSE);
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

	blob_buf_init(&buf, 0);

	if (cl->request.method != UH_HTTP_MSG_POST)
		return ops->client_error(cl, 400, "Bad Request", "Invalid Request");

	d->close_fds = uh_ubus_close_fds;
	d->free = uh_ubus_request_free;
	d->data_send = uh_ubus_data_send;
	d->data_done = uh_ubus_data_done;
	d->ubus.jstok = json_tokener_new();
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

const struct uhttpd_plugin uhttpd_plugin = {
	.init = uh_ubus_plugin_init,
	.post_init = uh_ubus_post_init,
};
