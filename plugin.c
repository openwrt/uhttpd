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
#include "plugin.h"

static LIST_HEAD(plugins);

static const struct uhttpd_ops ops = {
	.dispatch_add = uh_dispatch_add,
	.path_match = uh_path_match,
	.create_process = uh_create_process,
	.get_process_vars = uh_get_process_vars,
	.http_header = uh_http_header,
	.client_error = uh_client_error,
	.request_done = uh_request_done,
	.chunk_write = uh_chunk_write,
	.chunk_printf = uh_chunk_printf,
	.urlencode = uh_urlencode,
	.urldecode = uh_urldecode,
};

int uh_plugin_init(const char *name)
{
	struct uhttpd_plugin *p;
	const char *sym;
	void *dlh;

	dlh = dlopen(name, RTLD_LAZY | RTLD_LOCAL);
	if (!dlh) {
		fprintf(stderr, "Could not open plugin %s: %s\n", name, dlerror());
		return -ENOENT;
	}

	sym = "uhttpd_plugin";
	p = dlsym(dlh, sym);
	if (!p) {
		fprintf(stderr, "Could not find symbol '%s' in plugin '%s'\n", sym, name);
		return -ENOENT;
	}

	list_add(&p->list, &plugins);
	return p->init(&ops, &conf);
}

void uh_plugin_post_init(void)
{
	struct uhttpd_plugin *p;

	list_for_each_entry(p, &plugins, list)
		p->post_init();
}
