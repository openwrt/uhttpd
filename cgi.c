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

static LIST_HEAD(interpreters);

void uh_interpreter_add(const char *ext, const char *path)
{
	struct interpreter *in;
	char *new_ext, *new_path;

	in = calloc_a(sizeof(*in),
		&new_ext, strlen(ext) + 1,
		&new_path, strlen(path) + 1);

	in->ext = strcpy(new_ext, ext);
	in->path = strcpy(new_path, path);
	list_add_tail(&in->list, &interpreters);
}

static void cgi_main(struct client *cl, struct path_info *pi, int fd)
{
	const struct interpreter *ip = pi->ip;
	struct env_var *var;

	dup2(fd, 0);
	dup2(fd, 1);
	close(fd);
	clearenv();
	setenv("PATH", conf.cgi_path, 1);

	for (var = uh_get_process_vars(cl, pi); var->name; var++) {
		if (!var->value)
			continue;

		setenv(var->name, var->value, 1);
	}

	chdir(pi->root);

	if (ip)
		execl(ip->path, ip->path, pi->phys, NULL);
	else
		execl(pi->phys, pi->phys, NULL);

	printf("Status: 500 Internal Server Error\r\n\r\n"
	       "Unable to launch the requested CGI program:\n"
	       "  %s: %s\n", ip ? ip->path : pi->phys, strerror(errno));
}

static void cgi_handle_request(struct client *cl, const char *url, struct path_info *pi)
{
	unsigned int mode = S_IFREG | S_IXOTH;

	if (!pi->ip && !((pi->stat.st_mode & mode) == mode)) {
		uh_client_error(cl, 403, "Forbidden",
				"You don't have permission to access %s on this server.",
				url);
		return;
	}

	if (!uh_create_process(cl, pi, cgi_main)) {
		uh_client_error(cl, 500, "Internal Server Error",
				"Failed to create CGI process: %s", strerror(errno));
		return;
	}

	return;
}

static bool check_cgi_path(struct path_info *pi, const char *url)
{
	struct interpreter *ip;
	const char *path = pi->phys;
	int path_len = strlen(path);

	list_for_each_entry(ip, &interpreters, list) {
		int len = strlen(ip->ext);

		if (len >= path_len)
			continue;

		if (strcmp(path + path_len - len, ip->ext) != 0)
			continue;

		pi->ip = ip;
		return true;
	}

	pi->ip = NULL;
	return uh_path_match(conf.cgi_prefix, url);
}

struct dispatch_handler cgi_dispatch = {
	.check_path = check_cgi_path,
	.handle_request = cgi_handle_request,
};
