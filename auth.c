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

#define _GNU_SOURCE
#define _XOPEN_SOURCE	700
#include <strings.h>
#ifdef HAVE_SHADOW
#include <shadow.h>
#endif
#include "uhttpd.h"

static LIST_HEAD(auth_realms);

void uh_auth_add(const char *path, const char *user, const char *pass)
{
	struct auth_realm *new = NULL;
	struct passwd *pwd;
	const char *new_pass = NULL;
	char *dest_path, *dest_user, *dest_pass;

#ifdef HAVE_SHADOW
	struct spwd *spwd;
#endif

	/* given password refers to a passwd entry */
	if ((strlen(pass) > 3) && !strncmp(pass, "$p$", 3)) {
#ifdef HAVE_SHADOW
		/* try to resolve shadow entry */
		spwd = getspnam(&pass[3]);
		if (spwd)
			new_pass = spwd->sp_pwdp;
#endif
		if (!new_pass) {
			pwd = getpwnam(&pass[3]);
			if (pwd && pwd->pw_passwd && pwd->pw_passwd[0] &&
			    pwd->pw_passwd[0] != '!')
				new_pass = pwd->pw_passwd;
		}
	} else {
		new_pass = pass;
	}

	if (!new_pass || !new_pass[0])
		return;

	new = calloc_a(sizeof(*new),
		&dest_path, strlen(path) + 1,
		&dest_user, strlen(user) + 1,
		&dest_pass, strlen(new_pass) + 1);

	if (!new)
		return;

	new->path = strcpy(dest_path, path);
	new->user = strcpy(dest_user, user);
	new->pass = strcpy(dest_pass, new_pass);
	list_add(&new->list, &auth_realms);
}

bool uh_auth_check(struct client *cl, struct path_info *pi)
{
	struct http_request *req = &cl->request;
	struct auth_realm *realm;
	bool user_match = false;
	char *user = NULL;
	char *pass = NULL;
	int plen;

	if (pi->auth && !strncasecmp(pi->auth, "Basic ", 6)) {
		const char *auth = pi->auth + 6;

		uh_b64decode(uh_buf, sizeof(uh_buf), auth, strlen(auth));
		pass = strchr(uh_buf, ':');
		if (pass) {
			user = uh_buf;
			*pass++ = 0;
		}
	}

	req->realm = NULL;
	plen = strlen(pi->name);
	list_for_each_entry(realm, &auth_realms, list) {
		int rlen = strlen(realm->path);

		if (plen < rlen)
			continue;

		if (strncasecmp(pi->name, realm->path, rlen) != 0)
			continue;

		req->realm = realm;
		if (!user)
			break;

		if (strcmp(user, realm->user) != 0)
			continue;

		user_match = true;
		break;
	}

	if (!req->realm)
		return true;

	if (user_match && !strcmp(crypt(pass, realm->pass), realm->pass))
		return true;

	uh_http_header(cl, 401, "Authorization Required");
	ustream_printf(cl->us,
				  "WWW-Authenticate: Basic realm=\"%s\"\r\n"
				  "Content-Type: text/plain\r\n\r\n",
				  conf.realm);
	uh_chunk_printf(cl, "Authorization Required\n");
	uh_request_done(cl);

	return false;
}
