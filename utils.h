/*
 * uhttpd - Tiny single-threaded httpd - Utility header
 *
 *   Copyright (C) 2010-2012 Jo-Philipp Wich <xm@subsignal.org>
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

#ifndef _UHTTPD_UTILS_

#include <sys/stat.h>

#include <stdarg.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#define min(x, y) (((x) < (y)) ? (x) : (y))
#define max(x, y) (((x) > (y)) ? (x) : (y))

#define array_size(x) \
	(sizeof(x) / sizeof(x[0]))

#define fd_cloexec(fd) \
	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC)

#ifdef __APPLE__
static inline void clearenv(void)
{
	extern char **environ;
	*environ = NULL;
}
#endif

#ifdef __GNUC__
#define __printf(a, b) __attribute__((format(printf, a, b)))
#else
#define __printf(a, b)
#endif

int uh_urldecode(char *buf, int blen, const char *src, int slen);
int uh_urlencode(char *buf, int blen, const char *src, int slen);
int uh_b64decode(char *buf, int blen, const unsigned char *src, int slen);
bool uh_path_match(const char *prefix, const char *url);
char *uh_split_header(char *str);

#endif
