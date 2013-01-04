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

#ifndef __UHTTPD_TLS_H
#define __UHTTPD_TLS_H

#ifdef HAVE_TLS

int uh_tls_init(const char *key, const char *crt);
void uh_tls_client_attach(struct client *cl);
void uh_tls_client_detach(struct client *cl);

#else

static inline int uh_tls_init(const char *key, const char *crt)
{
	return -1;
}

static inline void uh_tls_client_attach(struct client *cl)
{
}

static inline void uh_tls_client_detach(struct client *cl)
{
}

#endif

#endif
