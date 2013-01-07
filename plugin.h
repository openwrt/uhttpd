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

#include "uhttpd.h"

struct uhttpd_ops {
	void (*dispatch_add)(struct dispatch_handler *d);
	bool (*path_match)(const char *prefix, const char *url);

	bool (*create_process)(struct client *cl, struct path_info *pi, char *url,
			       void (*cb)(struct client *cl, struct path_info *pi, char *url));
	struct env_var *(*get_process_vars)(struct client *cl, struct path_info *pi);

	void (*http_header)(struct client *cl, int code, const char *summary);
	void (*client_error)(struct client *cl, int code, const char *summary, const char *fmt, ...);
	void (*request_done)(struct client *cl);
	void (*chunk_write)(struct client *cl, const void *data, int len);

	int (*urlencode)(char *buf, int blen, const char *src, int slen);
	int (*urldecode)(char *buf, int blen, const char *src, int slen);
};

struct uhttpd_plugin {
	struct list_head list;

	int (*init)(const struct uhttpd_ops *ops, struct config *conf);
	void (*post_init)(void);
};
