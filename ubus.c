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
#include <fnmatch.h>
#include <stdio.h>
#include <poll.h>

#include "uhttpd.h"
#include "plugin.h"
#include "ubus.h"

static const struct uhttpd_ops *ops;
static struct config *_conf;
#define conf (*_conf)

static struct ubus_context *ctx;
static struct avl_tree sessions;
static struct blob_buf buf;

static const struct blobmsg_policy new_policy = {
	.name = "timeout", .type = BLOBMSG_TYPE_INT32
};

static const struct blobmsg_policy sid_policy = {
	.name = "sid", .type = BLOBMSG_TYPE_STRING
};

enum {
	UH_UBUS_SS_SID,
	UH_UBUS_SS_VALUES,
	__UH_UBUS_SS_MAX,
};
static const struct blobmsg_policy set_policy[__UH_UBUS_SS_MAX] = {
	[UH_UBUS_SS_SID] = { .name = "sid", .type = BLOBMSG_TYPE_STRING },
	[UH_UBUS_SS_VALUES] = { .name = "values", .type = BLOBMSG_TYPE_TABLE },
};

enum {
	UH_UBUS_SG_SID,
	UH_UBUS_SG_KEYS,
	__UH_UBUS_SG_MAX,
};
static const struct blobmsg_policy get_policy[__UH_UBUS_SG_MAX] = {
	[UH_UBUS_SG_SID] = { .name = "sid", .type = BLOBMSG_TYPE_STRING },
	[UH_UBUS_SG_KEYS] = { .name = "keys", .type = BLOBMSG_TYPE_ARRAY },
};

enum {
	UH_UBUS_SA_SID,
	UH_UBUS_SA_OBJECTS,
	__UH_UBUS_SA_MAX,
};
static const struct blobmsg_policy acl_policy[__UH_UBUS_SA_MAX] = {
	[UH_UBUS_SA_SID] = { .name = "sid", .type = BLOBMSG_TYPE_STRING },
	[UH_UBUS_SA_OBJECTS] = { .name = "objects", .type = BLOBMSG_TYPE_ARRAY },
};

/*
 * Keys in the AVL tree contain all pattern characters up to the first wildcard.
 * To look up entries, start with the last entry that has a key less than or
 * equal to the method name, then work backwards as long as the AVL key still
 * matches its counterpart in the object name
 */
#define uh_foreach_matching_acl_prefix(_acl, _ses, _obj, _func)			\
	for (_acl = avl_find_le_element(&(_ses)->acls, _obj, _acl, avl);	\
	     _acl;								\
	     _acl = avl_is_first(&(ses)->acls, &(_acl)->avl) ? NULL :		\
		    avl_prev_element((_acl), avl))

#define uh_foreach_matching_acl(_acl, _ses, _obj, _func)			\
	uh_foreach_matching_acl_prefix(_acl, _ses, _obj, _func)			\
		if (!strncmp((_acl)->object, _obj, (_acl)->sort_len) &&		\
		    !fnmatch((_acl)->object, (_obj), FNM_NOESCAPE) &&		\
		    !fnmatch((_acl)->function, (_func), FNM_NOESCAPE))

static void
uh_ubus_random(char *dest)
{
	unsigned char buf[16] = { 0 };
	FILE *f;
	int i;

	f = fopen("/dev/urandom", "r");
	if (!f)
		return;

	fread(buf, 1, sizeof(buf), f);
	fclose(f);

	for (i = 0; i < sizeof(buf); i++)
		sprintf(dest + (i<<1), "%02x", buf[i]);
}

static void
uh_ubus_session_dump_data(struct uh_ubus_session *ses, struct blob_buf *b)
{
	struct uh_ubus_session_data *d;

	avl_for_each_element(&ses->data, d, avl) {
		blobmsg_add_field(b, blobmsg_type(d->attr), blobmsg_name(d->attr),
				  blobmsg_data(d->attr), blobmsg_data_len(d->attr));
	}
}

static void
uh_ubus_session_dump_acls(struct uh_ubus_session *ses, struct blob_buf *b)
{
	struct uh_ubus_session_acl *acl;
	const char *lastobj = NULL;
	void *c = NULL;

	avl_for_each_element(&ses->acls, acl, avl) {
		if (!lastobj || strcmp(acl->object, lastobj))
		{
			if (c) blobmsg_close_array(b, c);
			c = blobmsg_open_array(b, acl->object);
		}

		blobmsg_add_string(b, NULL, acl->function);
		lastobj = acl->object;
	}

	if (c) blobmsg_close_array(b, c);
}

static void
uh_ubus_session_dump(struct uh_ubus_session *ses,
					 struct ubus_context *ctx,
					 struct ubus_request_data *req)
{
	void *c;
	struct blob_buf b;

	memset(&b, 0, sizeof(b));
	blob_buf_init(&b, 0);

	blobmsg_add_string(&b, "sid", ses->id);
	blobmsg_add_u32(&b, "timeout", ses->timeout);

	c = blobmsg_open_table(&b, "acls");
	uh_ubus_session_dump_acls(ses, &b);
	blobmsg_close_table(&b, c);

	c = blobmsg_open_table(&b, "data");
	uh_ubus_session_dump_data(ses, &b);
	blobmsg_close_table(&b, c);

	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);
}

static void
uh_ubus_touch_session(struct uh_ubus_session *ses)
{
	uloop_timeout_set(&ses->t, ses->timeout * 1000);
}

static void
uh_ubus_session_destroy(struct uh_ubus_session *ses)
{
	struct uh_ubus_session_acl *acl, *nacl;
	struct uh_ubus_session_data *data, *ndata;

	uloop_timeout_cancel(&ses->t);
	avl_remove_all_elements(&ses->acls, acl, avl, nacl)
		free(acl);

	avl_remove_all_elements(&ses->data, data, avl, ndata)
		free(data);

	avl_delete(&sessions, &ses->avl);
	free(ses);
}

static void uh_ubus_session_timeout(struct uloop_timeout *t)
{
	struct uh_ubus_session *ses;

	ses = container_of(t, struct uh_ubus_session, t);
	uh_ubus_session_destroy(ses);
}

static struct uh_ubus_session *
uh_ubus_session_create(int timeout)
{
	struct uh_ubus_session *ses;

	ses = calloc(1, sizeof(*ses));
	if (!ses)
		return NULL;

	ses->timeout  = timeout;
	ses->avl.key  = ses->id;
	uh_ubus_random(ses->id);

	avl_insert(&sessions, &ses->avl);
	avl_init(&ses->acls, avl_strcmp, true, NULL);
	avl_init(&ses->data, avl_strcmp, false, NULL);

	ses->t.cb = uh_ubus_session_timeout;
	uh_ubus_touch_session(ses);

	return ses;
}

static struct uh_ubus_session *
uh_ubus_session_get(const char *id)
{
	struct uh_ubus_session *ses;

	ses = avl_find_element(&sessions, id, ses, avl);
	if (!ses)
		return NULL;

	uh_ubus_touch_session(ses);
	return ses;
}

static int
uh_ubus_handle_create(struct ubus_context *ctx, struct ubus_object *obj,
					  struct ubus_request_data *req, const char *method,
					  struct blob_attr *msg)
{
	struct uh_ubus_session *ses;
	struct blob_attr *tb;
	int timeout = conf.script_timeout;

	blobmsg_parse(&new_policy, 1, &tb, blob_data(msg), blob_len(msg));
	if (tb)
		timeout = blobmsg_get_u32(tb);

	ses = uh_ubus_session_create(timeout);
	if (ses)
		uh_ubus_session_dump(ses, ctx, req);

	return 0;
}

static int
uh_ubus_handle_list(struct ubus_context *ctx, struct ubus_object *obj,
					struct ubus_request_data *req, const char *method,
					struct blob_attr *msg)
{
	struct uh_ubus_session *ses;
	struct blob_attr *tb;

	blobmsg_parse(&sid_policy, 1, &tb, blob_data(msg), blob_len(msg));

	if (!tb) {
		avl_for_each_element(&sessions, ses, avl)
			uh_ubus_session_dump(ses, ctx, req);
		return 0;
	}

	ses = uh_ubus_session_get(blobmsg_data(tb));
	if (!ses)
		return UBUS_STATUS_NOT_FOUND;

	uh_ubus_session_dump(ses, ctx, req);

	return 0;
}

static int
uh_id_len(const char *str)
{
	return strcspn(str, "*?[");
}

static int
uh_ubus_session_grant(struct uh_ubus_session *ses, struct ubus_context *ctx,
		      const char *object, const char *function)
{
	struct uh_ubus_session_acl *acl;
	char *new_obj, *new_func, *new_id;
	int id_len;

	if (!object || !function)
		return UBUS_STATUS_INVALID_ARGUMENT;

	uh_foreach_matching_acl_prefix(acl, ses, object, function) {
		if (!strcmp(acl->object, object) &&
		    !strcmp(acl->function, function))
			return 0;
	}

	id_len = uh_id_len(object);
	acl = calloc_a(sizeof(*acl),
		&new_obj, strlen(object) + 1,
		&new_func, strlen(function) + 1,
		&new_id, id_len + 1);

	if (!acl)
		return UBUS_STATUS_UNKNOWN_ERROR;

	acl->object = strcpy(new_obj, object);
	acl->function = strcpy(new_func, function);
	acl->avl.key = strncpy(new_id, object, id_len);
	avl_insert(&ses->acls, &acl->avl);

	return 0;
}

static int
uh_ubus_session_revoke(struct uh_ubus_session *ses, struct ubus_context *ctx,
		       const char *object, const char *function)
{
	struct uh_ubus_session_acl *acl, *next;
	int id_len;
	char *id;

	if (!object && !function) {
		avl_remove_all_elements(&ses->acls, acl, avl, next)
			free(acl);
		return 0;
	}

	id_len = uh_id_len(object);
	id = alloca(id_len + 1);
	strncpy(id, object, id_len);
	id[id_len] = 0;

	acl = avl_find_element(&ses->acls, id, acl, avl);
	while (acl) {
		if (!avl_is_last(&ses->acls, &acl->avl))
			next = avl_next_element(acl, avl);
		else
			next = NULL;

		if (strcmp(id, acl->avl.key) != 0)
			break;

		if (!strcmp(acl->object, object) &&
		    !strcmp(acl->function, function)) {
			avl_delete(&ses->acls, &acl->avl);
			free(acl);
		}
		acl = next;
	}

	return 0;
}


static int
uh_ubus_handle_acl(struct ubus_context *ctx, struct ubus_object *obj,
		   struct ubus_request_data *req, const char *method,
		   struct blob_attr *msg)
{
	struct uh_ubus_session *ses;
	struct blob_attr *tb[__UH_UBUS_SA_MAX];
	struct blob_attr *attr, *sattr;
	const char *object, *function;
	int rem1, rem2;

	int (*cb)(struct uh_ubus_session *ses, struct ubus_context *ctx,
		  const char *object, const char *function);

	blobmsg_parse(acl_policy, __UH_UBUS_SA_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UH_UBUS_SA_SID])
		return UBUS_STATUS_INVALID_ARGUMENT;

	ses = uh_ubus_session_get(blobmsg_data(tb[UH_UBUS_SA_SID]));
	if (!ses)
		return UBUS_STATUS_NOT_FOUND;

	if (!strcmp(method, "grant"))
		cb = uh_ubus_session_grant;
	else
		cb = uh_ubus_session_revoke;

	if (!tb[UH_UBUS_SA_OBJECTS])
		return cb(ses, ctx, NULL, NULL);

	blobmsg_for_each_attr(attr, tb[UH_UBUS_SA_OBJECTS], rem1) {
		if (blob_id(attr) != BLOBMSG_TYPE_ARRAY)
			continue;

		object = NULL;
		function = NULL;

		blobmsg_for_each_attr(sattr, attr, rem2) {
			if (blob_id(sattr) != BLOBMSG_TYPE_STRING)
				continue;

			if (!object)
				object = blobmsg_data(sattr);
			else if (!function)
				function = blobmsg_data(sattr);
			else
				break;
		}

		if (object && function)
			cb(ses, ctx, object, function);
	}

	return 0;
}

static int
uh_ubus_handle_set(struct ubus_context *ctx, struct ubus_object *obj,
				   struct ubus_request_data *req, const char *method,
				   struct blob_attr *msg)
{
	struct uh_ubus_session *ses;
	struct uh_ubus_session_data *data;
	struct blob_attr *tb[__UH_UBUS_SA_MAX];
	struct blob_attr *attr;
	int rem;

	blobmsg_parse(set_policy, __UH_UBUS_SS_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UH_UBUS_SS_SID] || !tb[UH_UBUS_SS_VALUES])
		return UBUS_STATUS_INVALID_ARGUMENT;

	ses = uh_ubus_session_get(blobmsg_data(tb[UH_UBUS_SS_SID]));
	if (!ses)
		return UBUS_STATUS_NOT_FOUND;

	blobmsg_for_each_attr(attr, tb[UH_UBUS_SS_VALUES], rem) {
		if (!blobmsg_name(attr)[0])
			continue;

		data = avl_find_element(&ses->data, blobmsg_name(attr), data, avl);
		if (data) {
			avl_delete(&ses->data, &data->avl);
			free(data);
		}

		data = calloc(1, sizeof(*data) + blob_pad_len(attr));
		if (!data)
			break;

		memcpy(data->attr, attr, blob_pad_len(attr));
		data->avl.key = blobmsg_name(data->attr);
		avl_insert(&ses->data, &data->avl);
	}

	return 0;
}

static int
uh_ubus_handle_get(struct ubus_context *ctx, struct ubus_object *obj,
				   struct ubus_request_data *req, const char *method,
				   struct blob_attr *msg)
{
	struct uh_ubus_session *ses;
	struct uh_ubus_session_data *data;
	struct blob_attr *tb[__UH_UBUS_SA_MAX];
	struct blob_attr *attr;
	struct blob_buf b;
	void *c;
	int rem;

	blobmsg_parse(get_policy, __UH_UBUS_SG_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UH_UBUS_SG_SID])
		return UBUS_STATUS_INVALID_ARGUMENT;

	ses = uh_ubus_session_get(blobmsg_data(tb[UH_UBUS_SG_SID]));
	if (!ses)
		return UBUS_STATUS_NOT_FOUND;

	memset(&b, 0, sizeof(b));
	blob_buf_init(&b, 0);
	c = blobmsg_open_table(&b, "values");

	if (!tb[UH_UBUS_SG_KEYS]) {
		uh_ubus_session_dump_data(ses, &b);
		return 0;
	}

	blobmsg_for_each_attr(attr, tb[UH_UBUS_SG_KEYS], rem) {
		if (blob_id(attr) != BLOBMSG_TYPE_STRING)
			continue;

		data = avl_find_element(&ses->data, blobmsg_data(attr), data, avl);
		if (!data)
			continue;

		blobmsg_add_field(&b, blobmsg_type(data->attr),
				  blobmsg_name(data->attr),
				  blobmsg_data(data->attr),
				  blobmsg_data_len(data->attr));
	}

	blobmsg_close_table(&b, c);
	ubus_send_reply(ctx, req, b.head);
	blob_buf_free(&b);

	return 0;
}

static int
uh_ubus_handle_unset(struct ubus_context *ctx, struct ubus_object *obj,
				     struct ubus_request_data *req, const char *method,
				     struct blob_attr *msg)
{
	struct uh_ubus_session *ses;
	struct uh_ubus_session_data *data, *ndata;
	struct blob_attr *tb[__UH_UBUS_SA_MAX];
	struct blob_attr *attr;
	int rem;

	blobmsg_parse(get_policy, __UH_UBUS_SG_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[UH_UBUS_SG_SID])
		return UBUS_STATUS_INVALID_ARGUMENT;

	ses = uh_ubus_session_get(blobmsg_data(tb[UH_UBUS_SG_SID]));
	if (!ses)
		return UBUS_STATUS_NOT_FOUND;

	if (!tb[UH_UBUS_SG_KEYS]) {
		avl_remove_all_elements(&ses->data, data, avl, ndata)
			free(data);
		return 0;
	}

	blobmsg_for_each_attr(attr, tb[UH_UBUS_SG_KEYS], rem) {
		if (blob_id(attr) != BLOBMSG_TYPE_STRING)
			continue;

		data = avl_find_element(&ses->data, blobmsg_data(attr), data, avl);
		if (!data)
			continue;

		avl_delete(&ses->data, &data->avl);
		free(data);
	}

	return 0;
}

static int
uh_ubus_handle_destroy(struct ubus_context *ctx, struct ubus_object *obj,
					   struct ubus_request_data *req, const char *method,
					   struct blob_attr *msg)
{
	struct uh_ubus_session *ses;
	struct blob_attr *tb;

	blobmsg_parse(&sid_policy, 1, &tb, blob_data(msg), blob_len(msg));

	if (!tb)
		return UBUS_STATUS_INVALID_ARGUMENT;

	ses = uh_ubus_session_get(blobmsg_data(tb));
	if (!ses)
		return UBUS_STATUS_NOT_FOUND;

	uh_ubus_session_destroy(ses);

	return 0;
}

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
	struct uh_ubus_session_acl *acl;
	struct uh_ubus_session *ses;
	struct dispatch *d = &cl->dispatch;
	char *sid, *obj, *fun;
	bool access = false;

	blob_buf_init(&buf, 0);

	if (!uh_ubus_request_parse_url(cl, url, &sid, &obj, &fun))
		return ops->client_error(cl, 400, "Bad Request", "Invalid Request");

	ses = uh_ubus_session_get(sid);
	if (!ses)
		return ops->client_error(cl, 404, "Not Found", "No such session %s", sid);

	uh_foreach_matching_acl(acl, ses, obj, fun) {
		access = true;
		break;
	}

	if (!access)
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

	static const struct ubus_method session_methods[] = {
		UBUS_METHOD("create",  uh_ubus_handle_create,  &new_policy),
		UBUS_METHOD("list",    uh_ubus_handle_list,    &sid_policy),
		UBUS_METHOD("grant",   uh_ubus_handle_acl,     acl_policy),
		UBUS_METHOD("revoke",  uh_ubus_handle_acl,     acl_policy),
		UBUS_METHOD("set",     uh_ubus_handle_set,     set_policy),
		UBUS_METHOD("get",     uh_ubus_handle_get,     get_policy),
		UBUS_METHOD("unset",   uh_ubus_handle_unset,   get_policy),
		UBUS_METHOD("destroy", uh_ubus_handle_destroy, &sid_policy),
	};

	static struct ubus_object_type session_type =
		UBUS_OBJECT_TYPE("uhttpd", session_methods);

	static struct ubus_object obj = {
		.name = "session",
		.type = &session_type,
		.methods = session_methods,
		.n_methods = ARRAY_SIZE(session_methods),
	};

	int ret;

	ctx = ubus_connect(conf.ubus_socket);
	if (!ctx) {
		fprintf(stderr, "Unable to connect to ubus socket\n");
		exit(1);
	}

	ret = ubus_add_object(ctx, &obj);
	if (ret) {
		fprintf(stderr, "Unable to publish ubus object: %s\n",
				ubus_strerror(ret));
		exit(1);
	}

	avl_init(&sessions, avl_strcmp, false, NULL);
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
