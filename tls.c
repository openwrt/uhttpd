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

#include <dlfcn.h>
#include "uhttpd.h"
#include "tls.h"

#ifdef __APPLE__
#define LIB_EXT "dylib"
#else
#define LIB_EXT "so"
#endif

static struct ustream_ssl_ops *ops;
static void *dlh;
static void *ctx;

int uh_tls_init(const char *key, const char *crt)
{
	static bool _init = false;

	if (_init)
		return 0;

	_init = true;
	dlh = dlopen("libustream-ssl." LIB_EXT, RTLD_LAZY | RTLD_LOCAL);
	if (!dlh) {
		fprintf(stderr, "Failed to load ustream-ssl library: %s\n", dlerror());
		return -ENOENT;
	}

	ops = dlsym(dlh, "ustream_ssl_ops");
	if (!ops) {
		fprintf(stderr, "Could not find required symbol 'ustream_ssl_ops' in ustream-ssl library\n");
		return -ENOENT;
	}

	ctx = ops->context_new(true);
	if (!ctx) {
		fprintf(stderr, "Failed to initialize ustream-ssl\n");
		return -EINVAL;
	}

	if (ops->context_set_crt_file(ctx, crt) ||
	    ops->context_set_key_file(ctx, key)) {
		fprintf(stderr, "Failed to load certificate/key files\n");
		return -EINVAL;
	}

	return 0;
}

static void tls_ustream_read_cb(struct ustream *s, int bytes)
{
	struct client *cl = container_of(s, struct client, ssl);

	uh_client_read_cb(cl);
}

static void tls_ustream_write_cb(struct ustream *s, int bytes)
{
	struct client *cl = container_of(s, struct client, ssl);

	if (cl->dispatch.write_cb)
		cl->dispatch.write_cb(cl);
}

static void tls_notify_state(struct ustream *s)
{
	struct client *cl = container_of(s, struct client, ssl);

	uh_client_notify_state(cl);
}

void uh_tls_client_attach(struct client *cl)
{
	cl->us = &cl->ssl.stream;
	ops->init(&cl->ssl, &cl->sfd.stream, ctx, true);
	cl->us->notify_read = tls_ustream_read_cb;
	cl->us->notify_write = tls_ustream_write_cb;
	cl->us->notify_state = tls_notify_state;
}

void uh_tls_client_detach(struct client *cl)
{
	ustream_free(&cl->ssl.stream);
}
