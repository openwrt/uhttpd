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

static void uh_config_parse(void)
{
	const char *path = conf.file;
	FILE *c;
	char line[512];
	char *col1;
	char *col2;
	char *eol;

	if (!path)
		path = "/etc/httpd.conf";

	c = fopen(path, "r");
	if (!c)
		return;

	memset(line, 0, sizeof(line));

	while (fgets(line, sizeof(line) - 1, c)) {
		if ((line[0] == '/') && (strchr(line, ':') != NULL)) {
			if (!(col1 = strchr(line, ':')) || (*col1++ = 0) ||
				!(col2 = strchr(col1, ':')) || (*col2++ = 0) ||
				!(eol = strchr(col2, '\n')) || (*eol++  = 0))
				continue;

			uh_auth_add(line, col1, col2);
		} else if (!strncmp(line, "I:", 2)) {
			if (!(col1 = strchr(line, ':')) || (*col1++ = 0) ||
				!(eol = strchr(col1, '\n')) || (*eol++  = 0))
				continue;

			uh_index_add(strdup(col1));
		} else if (!strncmp(line, "E404:", 5)) {
			if (!(col1 = strchr(line, ':')) || (*col1++ = 0) ||
				!(eol = strchr(col1, '\n')) || (*eol++  = 0))
				continue;

			conf.error_handler = strdup(col1);
		}
#ifdef HAVE_CGI
		else if ((line[0] == '*') && (strchr(line, ':') != NULL)) {
			if (!(col1 = strchr(line, '*')) || (*col1++ = 0) ||
				!(col2 = strchr(col1, ':')) || (*col2++ = 0) ||
				!(eol = strchr(col2, '\n')) || (*eol++  = 0))
				continue;

			if (!uh_interpreter_add(col1, col2))
				fprintf(stderr,
						"Unable to add interpreter %s for extension %s: "
						"Out of memory\n", col2, col1
				);
		}
#endif
	}

	fclose(c);
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
	bool nofork = false;
	char *port;
	int opt, ch;
	int cur_fd;

	init_defaults();
	signal(SIGPIPE, SIG_IGN);

	while ((ch = getopt(argc, argv, "fSDRC:K:E:I:p:s:h:c:l:L:d:r:m:n:x:i:t:T:A:u:U:")) != -1) {
		bool tls = false;

		switch(ch) {
		case 's':
			tls = true;
			/* fall through */
		case 'p':
			add_listener_arg(optarg, tls);
			break;

		case 'h':
			if (!realpath(optarg, conf.docroot)) {
				fprintf(stderr, "Error: Invalid directory %s: %s\n",
						optarg, strerror(errno));
				exit(1);
			}
			break;

		case 'E':
			if (optarg[0] != '/') {
				fprintf(stderr, "Error: Invalid error handler: %s\n",
						optarg);
				exit(1);
			}
			conf.error_handler = optarg;
			break;

		case 'I':
			if (optarg[0] == '/') {
				fprintf(stderr, "Error: Invalid index page: %s\n",
						optarg);
				exit(1);
			}
			uh_index_add(optarg);
			break;

		case 'S':
			conf.no_symlinks = 1;
			break;

		case 'D':
			conf.no_dirlists = 1;
			break;

		case 'R':
			conf.rfc1918_filter = 1;
			break;

		case 'n':
			conf.max_requests = atoi(optarg);
			break;

		case 't':
			conf.script_timeout = atoi(optarg);
			break;

		case 'T':
			conf.network_timeout = atoi(optarg);
			break;

		case 'A':
			conf.tcp_keepalive = atoi(optarg);
			break;

		case 'f':
			nofork = 1;
			break;

		case 'd':
			port = alloca(strlen(optarg) + 1);
			if (!port)
				return -1;

			/* "decode" plus to space to retain compat */
			for (opt = 0; optarg[opt]; opt++)
				if (optarg[opt] == '+')
					optarg[opt] = ' ';

			/* opt now contains strlen(optarg) -- no need to re-scan */
			if (uh_urldecode(port, opt, optarg, opt) < 0) {
				fprintf(stderr, "uhttpd: invalid encoding\n");
				return -1;
			}

			printf("%s", port);
			break;

		/* basic auth realm */
		case 'r':
			conf.realm = optarg;
			break;

		/* md5 crypt */
		case 'm':
			printf("%s\n", crypt(optarg, "$1$"));
			return 0;
			break;

		/* config file */
		case 'c':
			conf.file = optarg;
			break;

		default:
			return usage(argv[0]);
		}
	}

	uh_config_parse();

	/* fork (if not disabled) */
	if (!nofork) {
		switch (fork()) {
		case -1:
			perror("fork()");
			exit(1);

		case 0:
			/* daemon setup */
			if (chdir("/"))
				perror("chdir()");

			cur_fd = open("/dev/null", O_WRONLY);
			if (cur_fd > 0) {
				dup2(cur_fd, 0);
				dup2(cur_fd, 1);
				dup2(cur_fd, 2);
			}

			break;

		default:
			exit(0);
		}
	}

	return run_server();
}
