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
#include <libubox/blobmsg_json.h>
#include <libubox/avl.h>
#include <libubox/avl-cmp.h>
#include <stdio.h>
#include <poll.h>

#include "uhttpd.h"
#include "plugin.h"
#include "ubus-session.h"

static const struct uhttpd_ops *ops;
static struct config *_conf;
#define conf (*_conf)

static struct ubus_context *ctx;
static struct blob_buf buf;

#define UH_UBUS_MAX_POST_SIZE	4096

static char *split_str(char *str)
{
	if (str)
		str = strchr(str, '/');

	while (str && *str == '/') {
		*str = 0;
		str++;
	}
	return str;
}

static bool
uh_ubus_request_parse_url(struct client *cl, char *url, char **sid, char **obj, char **fun)
{
	url += strlen(conf.ubus_prefix);
	while (url && *url == '/')
		url++;

	*sid = url;

	url = split_str(url);
	*obj = url;

	url = split_str(url);
	*fun = url;

	return *sid && *obj && *fun;
}

static void
uh_ubus_request_data_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct dispatch_ubus *du = container_of(req, struct dispatch_ubus, req);
	struct client *cl = container_of(du, struct client, dispatch.ubus);
	char *str;

	if (!du->header_sent) {
		ops->http_header(cl, 200, "OK");
		ustream_printf(cl->us, "Content-Type: application/json\r\n\r\n");
		du->header_sent = true;
	}

	str = blobmsg_format_json_indent(msg, true, 0);
	ops->chunk_write(cl, str, strlen(str));
	free(str);
}

static void
uh_ubus_request_cb(struct ubus_request *req, int ret)
{
	struct dispatch_ubus *du = container_of(req, struct dispatch_ubus, req);
	struct client *cl = container_of(du, struct client, dispatch.ubus);

	if (!du->header_sent)
		return ops->client_error(cl, 204, "No content", "Function did not return data");

	ops->request_done(cl);
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

	if (du->jsobj)
		json_object_put(du->jsobj);

	if (du->jstok)
		json_tokener_free(du->jstok);

	if (du->req_pending)
		ubus_abort_request(ctx, &du->req);
}

static void uh_ubus_json_error(struct client *cl)
{
	ops->client_error(cl, 400, "Bad Request", "Invalid JSON data");
}

static void uh_ubus_send_request(struct client *cl, json_object *obj)
{
	struct dispatch *d = &cl->dispatch;
	struct dispatch_ubus *du = &d->ubus;
	int ret;

	blob_buf_init(&buf, 0);

	if (obj && !blobmsg_add_object(&buf, obj))
		return uh_ubus_json_error(cl);

	ret = ubus_invoke_async(ctx, du->obj, du->func, buf.head, &du->req);
	if (ret)
		return ops->client_error(cl, 500, "Internal Error",
			"Error sending ubus request: %s", ubus_strerror(ret));

	du->req.data_cb = uh_ubus_request_data_cb;
	du->req.complete_cb = uh_ubus_request_cb;
	ubus_complete_request_async(ctx, &du->req);

	du->req_pending = true;
}

static void uh_ubus_data_done(struct client *cl)
{
	struct dispatch_ubus *du = &cl->dispatch.ubus;
	struct json_object *obj = du->jsobj;

	if (!obj || json_object_get_type(obj) != json_type_object)
		return uh_ubus_json_error(cl);

	uh_ubus_send_request(cl, obj);
}

static int uh_ubus_data_send(struct client *cl, const char *data, int len)
{
	struct dispatch_ubus *du = &cl->dispatch.ubus;

	if (du->jsobj) {
		uh_ubus_json_error(cl);
		return 0;
	}

	du->post_len += len;
	if (du->post_len > UH_UBUS_MAX_POST_SIZE) {
		ops->client_error(cl, 413, "Too Large", "Message too big");
		return 0;
	}

	du->jsobj = json_tokener_parse_ex(du->jstok, data, len);
	return len;
}

static void uh_ubus_defer_post(struct client *cl)
{
	struct dispatch *d = &cl->dispatch;

	d->ubus.jstok = json_tokener_new();
	if (d->ubus.jstok)
		return ops->client_error(cl, 500, "Internal Error", "Internal Error");

	d->data_send = uh_ubus_data_send;
	d->data_done = uh_ubus_data_done;
}

static void uh_ubus_handle_request(struct client *cl, char *url, struct path_info *pi)
{
	struct uh_ubus_session *ses;
	struct dispatch *d = &cl->dispatch;
	char *sid, *obj, *fun;

	blob_buf_init(&buf, 0);

	if (!uh_ubus_request_parse_url(cl, url, &sid, &obj, &fun))
		return ops->client_error(cl, 400, "Bad Request", "Invalid Request");

	ses = uh_ubus_session_get(sid);
	if (!ses)
		return ops->client_error(cl, 404, "Not Found", "No such session %s", sid);

	if (!uh_ubus_session_acl_allowed(ses, obj, fun))
		return ops->client_error(cl, 403, "Denied", "Access to object denied");

	if (ubus_lookup_id(ctx, obj, &d->ubus.obj))
		return ops->client_error(cl, 500, "Not Found", "No such object");

	d->close_fds = uh_ubus_close_fds;
	d->free = uh_ubus_request_free;
	d->ubus.func = fun;

	if (cl->request.method == UH_HTTP_MSG_POST)
		uh_ubus_defer_post(cl);
	else
		uh_ubus_send_request(cl, NULL);
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
	if (ubus_session_api_init(ctx)) {
		fprintf(stderr, "Unable to initialize ubus session API\n");
		exit(1);
	}

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
