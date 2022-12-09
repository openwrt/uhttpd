/*
 * uhttpd - Tiny single-threaded httpd
 *
 *   Copyright (C) 2010-2013 Jo-Philipp Wich <xm@subsignal.org>
 *   Copyright (C) 2013 Felix Fietkau <nbd@openwrt.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <libubox/blobmsg.h>
#include <ucode/compiler.h>
#include <ucode/lib.h>
#include <ucode/vm.h>
#include <stdio.h>
#include <poll.h>

#include "uhttpd.h"
#include "plugin.h"

#define UH_UCODE_CB	"handle_request"

static const struct uhttpd_ops *ops;
static struct config *_conf;
#define conf (*_conf)

static struct ucode_prefix *current_prefix;

static uc_value_t *
uh_ucode_recv(uc_vm_t *vm, size_t nargs)
{
	static struct pollfd pfd = { .fd = STDIN_FILENO, .events = POLLIN };
	int data_len = 0, len = BUFSIZ, rlen, r;
	uc_value_t *v = uc_fn_arg(0);
	uc_stringbuf_t *buf;

	if (ucv_type(v) == UC_INTEGER) {
		len = ucv_int64_get(v);
	}
	else if (v != NULL) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Argument not an integer");

		return NULL;
	}

	buf = ucv_stringbuf_new();

	while (len > 0) {
		rlen = (len < BUFSIZ) ? len : BUFSIZ;

		if (printbuf_memset(buf, -1, 0, rlen)) {
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Out of memory");
			printbuf_free(buf);

			return NULL;
		}

		buf->bpos -= rlen;
		r = read(STDIN_FILENO, buf->buf + buf->bpos, rlen);

		if (r < 0) {
			if (errno == EWOULDBLOCK || errno == EAGAIN) {
				pfd.revents = 0;
				poll(&pfd, 1, 1000);

				if (pfd.revents & POLLIN)
					continue;
			}

			if (errno == EINTR)
				continue;

			if (!data_len)
				data_len = -1;

			break;
		}

		buf->bpos += r;
		data_len += r;
		len -= r;

		if (r != rlen)
			break;
	}

	if (data_len > 0) {
		/* add final guard \0 but do not count it */
		if (printbuf_memset(buf, -1, 0, 1)) {
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Out of memory");
			printbuf_free(buf);

			return NULL;
		}

		buf->bpos--;

		return ucv_stringbuf_finish(buf);
	}

	printbuf_free(buf);

	return NULL;
}

static uc_value_t *
uh_ucode_send(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *val;
	size_t arridx;
	ssize_t len = 0;
	char *p;

	for (arridx = 0; arridx < nargs; arridx++) {
		val = uc_fn_arg(arridx);

		if (ucv_type(val) == UC_STRING) {
			len += write(STDOUT_FILENO, ucv_string_get(val), ucv_string_length(val));
		}
		else if (val != NULL) {
			p = ucv_to_string(vm, val);
			len += p ? write(STDOUT_FILENO, p, strlen(p)) : 0;
			free(p);
		}
	}

	return ucv_int64_new(len);
}

static uc_value_t *
uh_ucode_strconvert(uc_vm_t *vm, size_t nargs, int (*convert)(char *, int, const char *, int))
{
	uc_value_t *val = uc_fn_arg(0);
	static char out_buf[4096];
	int out_len;
	char *p;

	if (ucv_type(val) == UC_STRING) {
		out_len = convert(out_buf, sizeof(out_buf),
			ucv_string_get(val), ucv_string_length(val));
	}
	else if (val != NULL) {
		p = ucv_to_string(vm, val);
		out_len = p ? convert(out_buf, sizeof(out_buf), p, strlen(p)) : 0;
		free(p);
	}
	else {
		out_len = 0;
	}

	if (out_len < 0) {
		const char *error;

		if (out_len == -1)
			error = "buffer overflow";
		else
			error = "malformed string";

		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
			"%s on URL conversion\n", error);

		return NULL;
	}

	return ucv_string_new_length(out_buf, out_len);
}

static uc_value_t *
uh_ucode_urldecode(uc_vm_t *vm, size_t nargs)
{
	return uh_ucode_strconvert(vm, nargs, ops->urldecode);
}

static uc_value_t *
uh_ucode_urlencode(uc_vm_t *vm, size_t nargs)
{
	return uh_ucode_strconvert(vm, nargs, ops->urlencode);
}

static uc_parse_config_t config = {
	.strict_declarations = false,
	.lstrip_blocks = true,
	.trim_blocks = true
};

static void
uh_ucode_exception(uc_vm_t *vm, uc_exception_t *ex)
{
	uc_value_t *ctx;

	if (ex->type == EXCEPTION_EXIT)
		return;

	printf("Status: 500 Internal Server Error\r\n\r\n"
	       "Exception while executing ucode program %s:\n",
	       current_prefix->handler);

	switch (ex->type) {
	case EXCEPTION_SYNTAX:    printf("Syntax error");    break;
	case EXCEPTION_RUNTIME:   printf("Runtime error");   break;
	case EXCEPTION_TYPE:      printf("Type error");      break;
	case EXCEPTION_REFERENCE: printf("Reference error"); break;
	default:                  printf("Error");
	}

	printf(": %s\n", ex->message);

	ctx = ucv_object_get(ucv_array_get(ex->stacktrace, 0), "context", NULL);

	if (ctx)
		printf("%s\n", ucv_string_get(ctx));
}

static void
uh_ucode_state_init(struct ucode_prefix *ucode)
{
	char *syntax_error = NULL;
	uc_vm_t *vm = &ucode->ctx;
	uc_program_t *handler;
	uc_vm_status_t status;
	uc_source_t *src;
	uc_value_t *v;
	int exitcode;

	uc_search_path_init(&config.module_search_path);
	uc_vm_init(vm, &config);
	uc_stdlib_load(uc_vm_scope_get(vm));

	/* build uhttpd api table */
	v = ucv_object_new(vm);

	ucv_object_add(v, "send", ucv_cfunction_new("send", uh_ucode_send));
	ucv_object_add(v, "sendc", ucv_get(ucv_object_get(v, "send", NULL)));
	ucv_object_add(v, "recv", ucv_cfunction_new("recv", uh_ucode_recv));
	ucv_object_add(v, "urldecode", ucv_cfunction_new("urldecode", uh_ucode_urldecode));
	ucv_object_add(v, "urlencode", ucv_cfunction_new("urlencode", uh_ucode_urlencode));
	ucv_object_add(v, "docroot", ucv_string_new(conf.docroot));

	ucv_object_add(uc_vm_scope_get(vm), "uhttpd", v);

	src = uc_source_new_file(ucode->handler);

	if (!src) {
		fprintf(stderr, "Error: Unable to open ucode handler: %s\n",
		        strerror(errno));

		exit(1);
	}

	handler = uc_compile(&config, src, &syntax_error);

	uc_source_put(src);

	if (!handler) {
		fprintf(stderr, "Error: Unable to compile ucode handler: %s\n",
		        syntax_error);

		exit(1);
	}

	free(syntax_error);

	vm->output = fopen("/dev/null", "w");

	if (!vm->output) {
		fprintf(stderr, "Error: Unable to open /dev/null for writing: %s\n",
		        strerror(errno));

		exit(1);
	}

	status = uc_vm_execute(vm, handler, &v);
	exitcode = (int)ucv_int64_get(v);

	uc_program_put(handler);
	ucv_put(v);

	switch (status) {
	case STATUS_OK:
		break;

	case STATUS_EXIT:
		fprintf(stderr, "Error: The ucode handler invoked exit(%d)\n", exitcode);
		exit(exitcode ? exitcode : 1);

	case ERROR_COMPILE:
		fprintf(stderr, "Error: Compilation error while executing ucode handler\n");
		exit(1);

	case ERROR_RUNTIME:
		fprintf(stderr, "Error: Runtime error while executing ucode handler\n");
		exit(2);
	}

	v = ucv_object_get(uc_vm_scope_get(vm), UH_UCODE_CB, NULL);

	if (!ucv_is_callable(v)) {
		fprintf(stderr, "Error: The ucode handler declares no " UH_UCODE_CB "() callback.\n");
		exit(1);
	}

	uc_vm_exception_handler_set(vm, uh_ucode_exception);

	ucv_gc(vm);

	fclose(vm->output);

	vm->output = stdout;
}

static void
ucode_main(struct client *cl, struct path_info *pi, char *url)
{
	uc_vm_t *vm = &current_prefix->ctx;
	uc_value_t *req, *hdr, *res;
	int path_len, prefix_len;
	struct blob_attr *cur;
	struct env_var *var;
	char *str;
	int rem;

	/* new env table for this request */
	req = ucv_object_new(vm);

	prefix_len = strlen(pi->name);
	path_len = strlen(url);
	str = strchr(url, '?');

	if (str) {
		if (*(str + 1))
			pi->query = str + 1;

		path_len = str - url;
	}

	if (prefix_len > 0 && pi->name[prefix_len - 1] == '/')
		prefix_len--;

	if (path_len > prefix_len) {
		ucv_object_add(req, "PATH_INFO",
			ucv_string_new_length(url + prefix_len, path_len - prefix_len));
	}

	for (var = ops->get_process_vars(cl, pi); var->name; var++) {
		if (!var->value)
			continue;

		ucv_object_add(req, var->name, ucv_string_new(var->value));
	}

	ucv_object_add(req, "HTTP_VERSION",
		ucv_double_new(0.9 + (cl->request.version / 10.0)));

	hdr = ucv_object_new(vm);

	blob_for_each_attr(cur, cl->hdr.head, rem)
		ucv_object_add(hdr, blobmsg_name(cur), ucv_string_new(blobmsg_data(cur)));

	ucv_object_add(req, "headers", hdr);

	res = uc_vm_invoke(vm, UH_UCODE_CB, 1, req);

	ucv_put(req);
	ucv_put(res);

	exit(0);
}

static void
ucode_handle_request(struct client *cl, char *url, struct path_info *pi)
{
	struct ucode_prefix *p;
	static struct path_info _pi;

	list_for_each_entry(p, &conf.ucode_prefix, list) {
		if (!ops->path_match(p->prefix, url))
			continue;

		pi = &_pi;
		pi->name = p->prefix;
		pi->phys = p->handler;

		current_prefix = p;

		if (!ops->create_process(cl, pi, url, ucode_main)) {
			ops->client_error(cl, 500, "Internal Server Error",
			                  "Failed to create CGI process: %s",
			                  strerror(errno));
		}

		return;
	}

	ops->client_error(cl, 500, "Internal Server Error",
	                  "Failed to lookup matching handler");
}

static bool
check_ucode_url(const char *url)
{
	struct ucode_prefix *p;

	list_for_each_entry(p, &conf.ucode_prefix, list)
		if (ops->path_match(p->prefix, url))
			return true;

	return false;
}

static struct dispatch_handler ucode_dispatch = {
	.script = true,
	.check_url = check_ucode_url,
	.handle_request = ucode_handle_request,
};

static int
ucode_plugin_init(const struct uhttpd_ops *o, struct config *c)
{
	struct ucode_prefix *p;

	ops = o;
	_conf = c;

	list_for_each_entry(p, &conf.ucode_prefix, list)
		uh_ucode_state_init(p);

	ops->dispatch_add(&ucode_dispatch);
	return 0;
}

struct uhttpd_plugin uhttpd_plugin = {
	.init = ucode_plugin_init,
};
