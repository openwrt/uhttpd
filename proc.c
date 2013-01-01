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
#include "uhttpd.h"

#define __headers \
	__header(accept) \
	__header(accept_charset) \
	__header(accept_encoding) \
	__header(accept_language) \
	__header(authorization) \
	__header(connection) \
	__header(cookie) \
	__header(host) \
	__header(referer) \
	__header(user_agent) \
	__header(content_type) \
	__header(content_length)

#undef __header
#define __header __enum_header
enum client_hdr {
	__headers
	__HDR_MAX,
};

#undef __header
#define __header __blobmsg_header
static const struct blobmsg_policy hdr_policy[__HDR_MAX] = {
	__headers
};

static const struct {
	const char *name;
	int idx;
} proc_header_env[] = {
	{ "HTTP_ACCEPT", HDR_accept },
	{ "HTTP_ACCEPT_CHARSET", HDR_accept_charset },
	{ "HTTP_ACCEPT_ENCODING", HDR_accept_encoding },
	{ "HTTP_ACCEPT_LANGUAGE", HDR_accept_language },
	{ "HTTP_AUTHORIZATION", HDR_authorization },
	{ "HTTP_CONNECTION", HDR_connection },
	{ "HTTP_COOKIE", HDR_cookie },
	{ "HTTP_HOST", HDR_host },
	{ "HTTP_REFERER", HDR_referer },
	{ "HTTP_USER_AGENT", HDR_user_agent },
	{ "CONTENT_TYPE", HDR_content_type },
	{ "CONTENT_LENGTH", HDR_content_length },
};

enum extra_vars {
	/* no update needed */
	_VAR_GW,
	_VAR_SOFTWARE,

	/* updated by uh_get_process_vars */
	VAR_SCRIPT_NAME,
	VAR_SCRIPT_FILE,
	VAR_DOCROOT,
	VAR_QUERY,
	VAR_REQUEST,
	VAR_PROTO,
	VAR_METHOD,
	VAR_PATH_INFO,
	VAR_USER,
	VAR_REDIRECT,

	__VAR_MAX,
};

static struct env_var extra_vars[] = {
	[_VAR_GW] = { "GATEWAY_INTERFACE", "CGI/1.1" },
	[_VAR_SOFTWARE] = { "SERVER_SOFTWARE", "uhttpd" },
	[VAR_SCRIPT_NAME] = { "SCRIPT_NAME" },
	[VAR_SCRIPT_FILE] = { "SCRIPT_FILENAME" },
	[VAR_DOCROOT] = { "DOCUMENT_ROOT" },
	[VAR_QUERY] = { "QUERY_STRING" },
	[VAR_REQUEST] = { "REQUEST_URI" },
	[VAR_PROTO] = { "SERVER_PROTOCOL" },
	[VAR_METHOD] = { "REQUEST_METHOD" },
	[VAR_PATH_INFO] = { "PATH_INFO" },
	[VAR_USER] = { "REMOTE_USER" },
	[VAR_REDIRECT] = { "REDIRECT_STATUS" },
};

struct env_var *uh_get_process_vars(struct client *cl, struct path_info *pi)
{
	struct http_request *req = &cl->request;
	struct blob_attr *data = cl->hdr.head;
	struct env_var *vars = (void *) uh_buf;
	struct blob_attr *tb[__HDR_MAX];
	static char buf[4];
	int len;
	int i;

	len = ARRAY_SIZE(proc_header_env);
	len += ARRAY_SIZE(extra_vars);
	len *= sizeof(struct env_var);

	BUILD_BUG_ON(sizeof(uh_buf) < len);

	extra_vars[VAR_SCRIPT_NAME].value = pi->name;
	extra_vars[VAR_SCRIPT_FILE].value = pi->phys;
	extra_vars[VAR_DOCROOT].value = pi->root;
	extra_vars[VAR_QUERY].value = pi->query ? pi->query : "";
	extra_vars[VAR_REQUEST].value = req->url;
	extra_vars[VAR_PROTO].value = http_versions[req->version];
	extra_vars[VAR_METHOD].value = http_methods[req->method];
	extra_vars[VAR_PATH_INFO].value = pi->info;
	extra_vars[VAR_USER].value = req->realm ? req->realm->user : NULL;

	snprintf(buf, sizeof(buf), "%d", req->redirect_status);
	extra_vars[VAR_REDIRECT].value = buf;

	blobmsg_parse(hdr_policy, __HDR_MAX, tb, blob_data(data), blob_len(data));
	for (i = 0; i < ARRAY_SIZE(proc_header_env); i++) {
		struct blob_attr *cur;

		cur = tb[proc_header_env[i].idx];
		vars[i].name = proc_header_env[i].name;
		vars[i].value = cur ? blobmsg_data(cur) : "";
	}

	memcpy(&vars[i], extra_vars, sizeof(extra_vars));
	i += ARRAY_SIZE(extra_vars);
	vars[i].name = NULL;
	vars[i].value = NULL;

	return vars;
}

static void proc_close_fds(struct client *cl)
{
	close(cl->dispatch.proc.r.sfd.fd.fd);
}

static void proc_handle_close(struct relay *r, int ret)
{
	if (r->header_cb) {
		uh_client_error(r->cl, 502, "Bad Gateway",
				"The process did not produce any response");
		return;
	}

	uh_request_done(r->cl);
}

static void proc_handle_header(struct relay *r, const char *name, const char *val)
{
	static char status_buf[64];
	struct client *cl = r->cl;
	char *sep;
	char buf[4];

	if (strcmp(name, "Status")) {
		sep = strchr(val, ' ');
		if (sep != val + 3)
			return;

		memcpy(buf, val, 3);
		buf[3] = 0;
		snprintf(status_buf, sizeof(status_buf), "%s", sep + 1);
		cl->dispatch.proc.status_msg = status_buf;
		return;
	}

	blobmsg_add_string(&cl->dispatch.proc.hdr, name, val);
}

static void proc_handle_header_end(struct relay *r)
{
	struct client *cl = r->cl;
	struct blob_attr *cur;
	int rem;

	uh_http_header(cl, cl->dispatch.proc.status_code, cl->dispatch.proc.status_msg);
	blob_for_each_attr(cur, cl->dispatch.proc.hdr.head, rem)
		ustream_printf(cl->us, "%s: %s\r\n", blobmsg_name(cur), blobmsg_data(cur));

	ustream_printf(cl->us, "\r\n");
}

static void proc_free(struct client *cl)
{
	uh_relay_free(&cl->dispatch.proc.r);
}

bool uh_create_process(struct client *cl, struct path_info *pi,
		       void (*cb)(struct client *cl, struct path_info *pi, int fd))
{
	int fds[2];
	int pid;

	blob_buf_init(&cl->dispatch.proc.hdr, 0);
	cl->dispatch.proc.status_code = 200;
	cl->dispatch.proc.status_msg = "OK";

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds))
		return false;

	pid = fork();
	if (pid < 0) {
		close(fds[0]);
		close(fds[1]);
		return false;
	}

	if (!pid) {
		close(fds[0]);
		uh_close_fds();
		cb(cl, pi, fds[1]);
		exit(0);
	}

	close(fds[1]);
	uh_relay_open(cl, &cl->dispatch.proc.r, fds[0], pid);
	cl->dispatch.free = proc_free;
	cl->dispatch.close_fds = proc_close_fds;
	cl->dispatch.proc.r.header_cb = proc_handle_header;
	cl->dispatch.proc.r.header_end = proc_handle_header_end;
	cl->dispatch.proc.r.close = proc_handle_close;

	return true;
}
