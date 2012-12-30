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

	new = calloc(1, sizeof(*new));
	if (!new)
		return;

	snprintf(new->path, sizeof(new->path), "%s", path);
	snprintf(new->user, sizeof(new->user), "%s", user);
	snprintf(new->pass, sizeof(new->user), "%s", new_pass);
	list_add(&new->list, &auth_realms);
}
