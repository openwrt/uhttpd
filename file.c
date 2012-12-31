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

#define _BSD_SOURCE
#define _XOPEN_SOURCE 700

#include <sys/types.h>
#include <sys/dir.h>
#include <time.h>
#include <strings.h>

#include <libubox/blobmsg.h>

#include "uhttpd.h"
#include "uhttpd-mimetypes.h"

static LIST_HEAD(index_files);

struct index_file {
	struct list_head list;
	const char *name;
};

struct path_info {
	char *root;
	char *phys;
	char *name;
	char *info;
	char *query;
	int redirected;
	struct stat stat;
};

enum file_hdr {
	HDR_IF_MODIFIED_SINCE,
	HDR_IF_UNMODIFIED_SINCE,
	HDR_IF_MATCH,
	HDR_IF_NONE_MATCH,
	HDR_IF_RANGE,
	__HDR_MAX
};

void uh_index_add(const char *filename)
{
	struct index_file *idx;

	idx = calloc(1, sizeof(*idx));
	idx->name = filename;
	list_add_tail(&idx->list, &index_files);
}

static char * canonpath(const char *path, char *path_resolved)
{
	char path_copy[PATH_MAX];
	char *path_cpy = path_copy;
	char *path_res = path_resolved;
	struct stat s;

	/* relative -> absolute */
	if (*path != '/') {
		getcwd(path_copy, PATH_MAX);
		strncat(path_copy, "/", PATH_MAX - strlen(path_copy));
		strncat(path_copy, path, PATH_MAX - strlen(path_copy));
	} else {
		strncpy(path_copy, path, PATH_MAX);
	}

	/* normalize */
	while ((*path_cpy != '\0') && (path_cpy < (path_copy + PATH_MAX - 2))) {
		if (*path_cpy != '/')
			goto next;

		/* skip repeating / */
		if (path_cpy[1] == '/') {
			path_cpy++;
			continue;
		}

		/* /./ or /../ */
		if (path_cpy[1] == '.') {
			/* skip /./ */
			if ((path_cpy[2] == '/') || (path_cpy[2] == '\0')) {
				path_cpy += 2;
				continue;
			}

			/* collapse /x/../ */
			if ((path_cpy[2] == '.') &&
			    ((path_cpy[3] == '/') || (path_cpy[3] == '\0'))) {
				while ((path_res > path_resolved) && (*--path_res != '/'));

				path_cpy += 3;
				continue;
			}
		}

next:
		*path_res++ = *path_cpy++;
	}

	/* remove trailing slash if not root / */
	if ((path_res > (path_resolved+1)) && (path_res[-1] == '/'))
		path_res--;
	else if (path_res == path_resolved)
		*path_res++ = '/';

	*path_res = '\0';

	/* test access */
	if (!stat(path_resolved, &s) && (s.st_mode & S_IROTH))
		return path_resolved;

	return NULL;
}

/* Returns NULL on error.
** NB: improperly encoded URL should give client 400 [Bad Syntax]; returning
** NULL here causes 404 [Not Found], but that's not too unreasonable. */
struct path_info * uh_path_lookup(struct client *cl, const char *url)
{
	static char path_phys[PATH_MAX];
	static char path_info[PATH_MAX];
	static struct path_info p;

	char buffer[UH_LIMIT_MSGHEAD];
	char *docroot = conf.docroot;
	char *pathptr = NULL;

	int slash = 0;
	int no_sym = conf.no_symlinks;
	int i = 0;
	struct stat s;
	struct index_file *idx;

	/* back out early if url is undefined */
	if (url == NULL)
		return NULL;

	memset(path_phys, 0, sizeof(path_phys));
	memset(path_info, 0, sizeof(path_info));
	memset(buffer, 0, sizeof(buffer));
	memset(&p, 0, sizeof(p));

	/* copy docroot */
	memcpy(buffer, docroot,
		   min(strlen(docroot), sizeof(buffer) - 1));

	/* separate query string from url */
	if ((pathptr = strchr(url, '?')) != NULL) {
		p.query = pathptr[1] ? pathptr + 1 : NULL;

		/* urldecode component w/o query */
		if (pathptr > url) {
			if (uh_urldecode(&buffer[strlen(docroot)],
							 sizeof(buffer) - strlen(docroot) - 1,
							 url, pathptr - url ) < 0)
				return NULL; /* bad URL */
		}
	}

	/* no query string, decode all of url */
	else if (uh_urldecode(&buffer[strlen(docroot)],
			      sizeof(buffer) - strlen(docroot) - 1,
			      url, strlen(url) ) < 0)
		return NULL; /* bad URL */

	/* create canon path */
	for (i = strlen(buffer), slash = (buffer[max(0, i-1)] == '/'); i >= 0; i--) {
		if ((buffer[i] == 0) || (buffer[i] == '/')) {
			memset(path_info, 0, sizeof(path_info));
			memcpy(path_info, buffer, min(i + 1, sizeof(path_info) - 1));

			if (no_sym ? realpath(path_info, path_phys)
			           : canonpath(path_info, path_phys)) {
				memset(path_info, 0, sizeof(path_info));
				memcpy(path_info, &buffer[i],
					   min(strlen(buffer) - i, sizeof(path_info) - 1));

				break;
			}
		}
	}

	/* check whether found path is within docroot */
	if (strncmp(path_phys, docroot, strlen(docroot)) ||
		((path_phys[strlen(docroot)] != 0) &&
		 (path_phys[strlen(docroot)] != '/')))
		return NULL;

	/* test current path */
	if (!stat(path_phys, &p.stat)) {
		/* is a regular file */
		if (p.stat.st_mode & S_IFREG) {
			p.root = docroot;
			p.phys = path_phys;
			p.name = &path_phys[strlen(docroot)];
			p.info = path_info[0] ? path_info : NULL;
		}

		/* is a directory */
		else if ((p.stat.st_mode & S_IFDIR) && !strlen(path_info)) {
			/* ensure trailing slash */
			if (path_phys[strlen(path_phys)-1] != '/')
				path_phys[strlen(path_phys)] = '/';

			/* try to locate index file */
			memset(buffer, 0, sizeof(buffer));
			memcpy(buffer, path_phys, sizeof(buffer));
			pathptr = &buffer[strlen(buffer)];

			/* if requested url resolves to a directory and a trailing slash
			   is missing in the request url, redirect the client to the same
			   url with trailing slash appended */
			if (!slash) {
				uh_http_header(cl, 302, "Found");
				ustream_printf(cl->us, "Location: %s%s%s\r\n\r\n",
						&path_phys[strlen(docroot)],
						p.query ? "?" : "",
						p.query ? p.query : "");
				uh_request_done(cl);
				p.redirected = 1;
			} else {
				list_for_each_entry(idx, &index_files, list) {
					strncat(buffer, idx->name, sizeof(buffer));

					if (!stat(buffer, &s) && (s.st_mode & S_IFREG)) {
						memcpy(path_phys, buffer, sizeof(path_phys));
						memcpy(&p.stat, &s, sizeof(p.stat));
						break;
					}

					*pathptr = 0;
				}
			}

			p.root = docroot;
			p.phys = path_phys;
			p.name = &path_phys[strlen(docroot)];
		}
	}

	return p.phys ? &p : NULL;
}

#ifdef __APPLE__
time_t timegm (struct tm *tm);
#endif

static const char * uh_file_mime_lookup(const char *path)
{
	struct mimetype *m = &uh_mime_types[0];
	const char *e;

	while (m->extn) {
		e = &path[strlen(path)-1];

		while (e >= path) {
			if ((*e == '.' || *e == '/') && !strcasecmp(&e[1], m->extn))
				return m->mime;

			e--;
		}

		m++;
	}

	return "application/octet-stream";
}

static const char * uh_file_mktag(struct stat *s)
{
	static char tag[128];

	snprintf(tag, sizeof(tag), "\"%x-%x-%x\"",
			 (unsigned int) s->st_ino,
			 (unsigned int) s->st_size,
			 (unsigned int) s->st_mtime);

	return tag;
}

static time_t uh_file_date2unix(const char *date)
{
	struct tm t;

	memset(&t, 0, sizeof(t));

	if (strptime(date, "%a, %d %b %Y %H:%M:%S %Z", &t) != NULL)
		return timegm(&t);

	return 0;
}

static char * uh_file_unix2date(time_t ts)
{
	static char str[128];
	struct tm *t = gmtime(&ts);

	strftime(str, sizeof(str), "%a, %d %b %Y %H:%M:%S GMT", t);

	return str;
}

static char *uh_file_header(struct client *cl, int idx)
{
	if (!cl->data.file.hdr[idx])
		return NULL;

	return (char *) blobmsg_data(cl->data.file.hdr[idx]);
}

static void uh_file_response_ok_hdrs(struct client *cl, struct stat *s)
{
	if (s) {
		ustream_printf(cl->us, "ETag: %s\r\n", uh_file_mktag(s));
		ustream_printf(cl->us, "Last-Modified: %s\r\n",
			       uh_file_unix2date(s->st_mtime));
	}
	ustream_printf(cl->us, "Date: %s\r\n", uh_file_unix2date(time(NULL)));
}

static void uh_file_response_200(struct client *cl, struct stat *s)
{
	uh_http_header(cl, 200, "OK");
	return uh_file_response_ok_hdrs(cl, s);
}

static void uh_file_response_304(struct client *cl, struct stat *s)
{
	uh_http_header(cl, 304, "Not Modified");

	return uh_file_response_ok_hdrs(cl, s);
}

static void uh_file_response_412(struct client *cl)
{
	uh_http_header(cl, 412, "Precondition Failed");
}

static bool uh_file_if_match(struct client *cl, struct stat *s)
{
	const char *tag = uh_file_mktag(s);
	char *hdr = uh_file_header(cl, HDR_IF_MATCH);
	char *p;
	int i;

	if (!hdr)
		return true;

	p = &hdr[0];
	for (i = 0; i < strlen(hdr); i++)
	{
		if ((hdr[i] == ' ') || (hdr[i] == ',')) {
			hdr[i++] = 0;
			p = &hdr[i];
		} else if (!strcmp(p, "*") || !strcmp(p, tag)) {
			return true;
		}
	}

	uh_file_response_412(cl);
	return false;
}

static int uh_file_if_modified_since(struct client *cl, struct stat *s)
{
	char *hdr = uh_file_header(cl, HDR_IF_MODIFIED_SINCE);

	if (!hdr)
		return true;

	if (uh_file_date2unix(hdr) >= s->st_mtime) {
		uh_file_response_304(cl, s);
		return false;
	}

	return true;
}

static int uh_file_if_none_match(struct client *cl, struct stat *s)
{
	const char *tag = uh_file_mktag(s);
	char *hdr = uh_file_header(cl, HDR_IF_NONE_MATCH);
	char *p;
	int i;

	if (!hdr)
		return true;

	p = &hdr[0];
	for (i = 0; i < strlen(hdr); i++) {
		if ((hdr[i] == ' ') || (hdr[i] == ',')) {
			hdr[i++] = 0;
			p = &hdr[i];
		} else if (!strcmp(p, "*") || !strcmp(p, tag)) {
			if ((cl->request.method == UH_HTTP_MSG_GET) ||
				(cl->request.method == UH_HTTP_MSG_HEAD))
				uh_file_response_304(cl, s);
			else
				uh_file_response_412(cl);

			return false;
		}
	}

	return true;
}

static int uh_file_if_range(struct client *cl, struct stat *s)
{
	char *hdr = uh_file_header(cl, HDR_IF_RANGE);

	if (hdr) {
		uh_file_response_412(cl);
		return false;
	}

	return true;
}

static int uh_file_if_unmodified_since(struct client *cl, struct stat *s)
{
	char *hdr = uh_file_header(cl, HDR_IF_UNMODIFIED_SINCE);

	if (hdr && uh_file_date2unix(hdr) <= s->st_mtime) {
		uh_file_response_412(cl);
		return false;
	}

	return true;
}


static int uh_file_scandir_filter_dir(const struct dirent *e)
{
	return strcmp(e->d_name, ".") ? 1 : 0;
}

static void uh_file_dirlist(struct client *cl, struct path_info *pi)
{
	int i;
	int count = 0;
	char filename[PATH_MAX];
	char *pathptr;
	struct dirent **files = NULL;
	struct stat s;

	uh_file_response_200(cl, NULL);
	ustream_printf(cl->us, "Content-Type: text/html\r\n\r\n");

	uh_chunk_printf(cl,
		"<html><head><title>Index of %s</title></head>"
		"<body><h1>Index of %s</h1><hr /><ol>",
		pi->name, pi->name);

	if ((count = scandir(pi->phys, &files, uh_file_scandir_filter_dir,
						 alphasort)) > 0)
	{
		memset(filename, 0, sizeof(filename));
		memcpy(filename, pi->phys, sizeof(filename));
		pathptr = &filename[strlen(filename)];

		/* list subdirs */
		for (i = 0; i < count; i++) {
			strncat(filename, files[i]->d_name,
					sizeof(filename) - strlen(files[i]->d_name));

			if (!stat(filename, &s) &&
				(s.st_mode & S_IFDIR) && (s.st_mode & S_IXOTH))
				uh_chunk_printf(cl,
					"<li><strong><a href='%s%s'>%s</a>/"
					"</strong><br /><small>modified: %s"
					"<br />directory - %.02f kbyte<br />"
					"<br /></small></li>",
					pi->name, files[i]->d_name,
					files[i]->d_name,
					uh_file_unix2date(s.st_mtime),
					s.st_size / 1024.0);

			*pathptr = 0;
		}

		/* list files */
		for (i = 0; i < count; i++) {
			strncat(filename, files[i]->d_name,
					sizeof(filename) - strlen(files[i]->d_name));

			if (!stat(filename, &s) &&
				!(s.st_mode & S_IFDIR) && (s.st_mode & S_IROTH))
				uh_chunk_printf(cl,
					"<li><strong><a href='%s%s'>%s</a>"
					"</strong><br /><small>modified: %s"
					"<br />%s - %.02f kbyte<br />"
					"<br /></small></li>",
					pi->name, files[i]->d_name,
					files[i]->d_name,
					uh_file_unix2date(s.st_mtime),
					uh_file_mime_lookup(filename),
					s.st_size / 1024.0);

			*pathptr = 0;
		}
	}

	uh_chunk_printf(cl, "</ol><hr /></body></html>");
	uh_request_done(cl);

	if (files)
	{
		for (i = 0; i < count; i++)
			free(files[i]);

		free(files);
	}
}

static void file_write_cb(struct client *cl)
{
	char buf[512];
	int fd = cl->data.file.fd;
	int r;

	while (cl->us->w.data_bytes < 256) {
		r = read(fd, buf, sizeof(buf));
		if (r < 0) {
			if (errno == EINTR)
				continue;
		}

		if (!r) {
			uh_request_done(cl);
			return;
		}

		uh_chunk_write(cl, buf, r);
	}
}

static void uh_file_free(struct client *cl)
{
	close(cl->data.file.fd);
}

static void uh_file_data(struct client *cl, struct path_info *pi, int fd)
{
	/* test preconditions */
	if (!uh_file_if_modified_since(cl, &pi->stat) ||
		!uh_file_if_match(cl, &pi->stat) ||
		!uh_file_if_range(cl, &pi->stat) ||
		!uh_file_if_unmodified_since(cl, &pi->stat) ||
		!uh_file_if_none_match(cl, &pi->stat)) {
		uh_request_done(cl);
		close(fd);
		return;
	}

	/* write status */
	uh_file_response_200(cl, &pi->stat);

	ustream_printf(cl->us, "Content-Type: %s\r\n",
			   uh_file_mime_lookup(pi->name));

	ustream_printf(cl->us, "Content-Length: %i\r\n\r\n",
			   pi->stat.st_size);


	/* send body */
	if (cl->request.method == UH_HTTP_MSG_HEAD) {
		uh_request_done(cl);
		close(fd);
		return;
	}

	cl->data.file.fd = fd;
	cl->dispatch_write_cb = file_write_cb;
	cl->dispatch_free = uh_file_free;
	file_write_cb(cl);
}

static void uh_file_request(struct client *cl, struct path_info *pi)
{
	static const struct blobmsg_policy hdr_policy[__HDR_MAX] = {
		[HDR_IF_MODIFIED_SINCE] = { "if-modified-since", BLOBMSG_TYPE_STRING },
		[HDR_IF_UNMODIFIED_SINCE] = { "if-unmodified-since", BLOBMSG_TYPE_STRING },
		[HDR_IF_MATCH] = { "if-match", BLOBMSG_TYPE_STRING },
		[HDR_IF_NONE_MATCH] = { "if-none-match", BLOBMSG_TYPE_STRING },
		[HDR_IF_RANGE] = { "if-range", BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *tb[__HDR_MAX];
	int fd;

	blobmsg_parse(hdr_policy, __HDR_MAX, tb, blob_data(cl->hdr.head), blob_len(cl->hdr.head));

	cl->data.file.hdr = tb;
	if ((pi->stat.st_mode & S_IFREG) && ((fd = open(pi->phys, O_RDONLY)) > 0))
		uh_file_data(cl, pi, fd);
	else if ((pi->stat.st_mode & S_IFDIR) && !conf.no_dirlists)
		uh_file_dirlist(cl, pi);
	else
		uh_client_error(cl, 403, "Forbidden",
				"Access to this resource is forbidden");
	cl->data.file.hdr = NULL;
}

static bool __handle_file_request(struct client *cl, const char *url)
{
	struct path_info *pi;

	pi = uh_path_lookup(cl, url);
	if (!pi)
		return false;

	if (!pi->redirected)
		uh_file_request(cl, pi);

	return true;
}

void uh_handle_file_request(struct client *cl)
{
	if (__handle_file_request(cl, cl->request.url) ||
	    __handle_file_request(cl, conf.error_handler))
		return;

	uh_client_error(cl, 404, "Not Found", "No such file or directory");
}
