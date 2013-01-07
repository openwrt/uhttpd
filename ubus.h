/*
 * uhttpd - Tiny single-threaded httpd
 *
 *   Copyright (C) 2012 Jo-Philipp Wich <xm@subsignal.org>
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

#ifndef __UHTTPD_UBUS_H
#define __UHTTPD_UBUS_H

#include <libubox/avl.h>
#include <libubox/blobmsg_json.h>

#define UBUS_SID_LEN	32
#define UH_UBUS_MAX_POST_SIZE	4096

struct uh_ubus_request_data {
	const char *sid;
	const char *object;
	const char *function;
};

struct uh_ubus_session {
	struct avl_node avl;
	char id[UBUS_SID_LEN + 1];

	struct uloop_timeout t;
	struct avl_tree data;
	struct avl_tree acls;

	int timeout;
};

struct uh_ubus_session_data {
	struct avl_node avl;
	struct blob_attr attr[];
};

struct uh_ubus_session_acl {
	struct avl_node avl;
	const char *object;
	const char *function;
	int sort_len;
};

#endif
