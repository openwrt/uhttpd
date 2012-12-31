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
