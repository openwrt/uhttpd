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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <getopt.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>

#include <libubox/usock.h>

#include "uhttpd.h"


static int run_server(void)
{
	uloop_init();
	uh_setup_listeners();
	uloop_run();

	return 0;
}

static void add_listener_arg(char *arg, bool tls)
{
	char *host = NULL;
	char *port = arg;
	char *s;

	s = strrchr(arg, ':');
	if (s) {
		host = arg;
		port = s + 1;
		*s = 0;
	}
	uh_socket_bind(host, port, tls);
}

static int usage(const char *name)
{
	fprintf(stderr, "Usage: %s -p <port>\n", name);
	return 1;
}

static void init_defaults(void)
{
	conf.network_timeout = 30;
	conf.http_keepalive = 0; /* fixme */
	conf.max_requests = 3;

	uh_index_add("index.html");
	uh_index_add("index.htm");
	uh_index_add("default.html");
	uh_index_add("default.htm");
}

int main(int argc, char **argv)
{
	int ch;

	init_defaults();
	signal(SIGPIPE, SIG_IGN);

	while ((ch = getopt(argc, argv, "sp:h:")) != -1) {
		bool tls = false;
		switch(ch) {
		case 's':
			tls = true;
		case 'p':
			add_listener_arg(optarg, tls);
			break;

		case 'h':
			/* docroot */
			if (!realpath(optarg, conf.docroot)) {
				fprintf(stderr, "Error: Invalid directory %s: %s\n",
						optarg, strerror(errno));
				exit(1);
			}
			break;
		default:
			return usage(argv[0]);
		}
	}

	return run_server();
}
