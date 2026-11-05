#!/usr/bin/env python3
"""
Regression tests for the ubus JSON-RPC "list" response encoding.

Covers GHSA-788h-w5m4-j5xv: uhttpd's list callback opened one nesting level
per signature method of every object returned by a lookup and closed the
returned cookie without checking it. A JSON-RPC "list" request naming enough
object paths made the accumulated response blob approach the 24 bit length
limit of libubox blobs (BLOB_ATTR_LEN_MASK). Appending more data then fails,
blobmsg_open_nested() returns NULL and blobmsg_close_table(buf, NULL) treats
that cookie as an offset into the buffer ((char *)buf->buf - BLOB_COOKIE),
corrupting the blob header and eventually arbitrary heap. On the reported
target this was shaped into unauthenticated remote code execution.

The tests run uhttpd against a throwaway ubusd holding synthetic objects with
large signatures and check that:

  1. an unauthenticated verbose list still works,
  2. a single wildcard lookup over JSON-RPC still works,
  3. a request repeating the same lookup path is encoded once instead of
     once per repetition (the request from the advisory),
  4. a request whose result would outgrow the response budget is answered
     with a bounded JSON-RPC error and uhttpd survives it,
  5. more object paths than allowed are rejected as invalid params,
  6. the "call" and batched request paths still produce well formed answers,
  7. normal list requests are still served after all of the above,
  8. an unparameterized GET list which no longer fits is refused with a
     bounded HTTP 500 instead of being truncated.

Usage: ubus_list_encoding.py /path/to/uhttpd [-v] [--keep] [--objects N]
       [--oversize-objects N]

Needs ubusd plus a C compiler with libubus/libubox headers to build the fake
object provider. The test is skipped (exit code 0) when those are missing.
"""

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

PROVIDER_SRC = r"""
/* Registers synthetic ubus objects with large signatures, so that a single
 * wildcard lookup already returns a sizeable verbose list blob. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubus.h>

static struct ubus_context *ctx;

int main(int argc, char **argv)
{
	const char *sock = argc > 1 ? argv[1] : NULL;
	int nobj = argc > 2 ? atoi(argv[2]) : 60;
	int nmeth = argc > 3 ? atoi(argv[3]) : 30;
	int nargs = argc > 4 ? atoi(argv[4]) : 15;
	struct ubus_object *objs;
	struct ubus_object_type *types;
	struct ubus_method *meths;
	struct blobmsg_policy *pols;
	char name[64], meth[64], arg[32];
	int i, m, a;

	if (!sock) {
		fprintf(stderr, "usage: %s <ubus-socket> [objects] [methods] [args]\n", argv[0]);
		return 1;
	}

	objs = calloc(nobj, sizeof(*objs));
	types = calloc(nobj, sizeof(*types));
	meths = calloc(nobj * nmeth, sizeof(*meths));
	pols = calloc(nobj * nmeth * nargs, sizeof(*pols));
	if (!objs || !types || !meths || !pols)
		return 1;

	uloop_init();

	ctx = ubus_connect(sock);
	if (!ctx) {
		fprintf(stderr, "ubus_connect(%s) failed\n", sock);
		return 1;
	}

	for (i = 0; i < nobj; i++) {
		struct ubus_object_type *t = &types[i];

		snprintf(name, sizeof(name), "probe%03d", i);

		t->name = strdup(name);
		t->methods = &meths[i * nmeth];
		t->n_methods = nmeth;

		for (m = 0; m < nmeth; m++) {
			struct ubus_method *mm = &meths[i * nmeth + m];
			struct blobmsg_policy *pp = &pols[(i * nmeth + m) * nargs];

			snprintf(meth, sizeof(meth), "method%02d", m);

			mm->name = strdup(meth);
			mm->mask = 0;
			mm->policy = pp;
			mm->n_policy = nargs;

			for (a = 0; a < nargs; a++) {
				snprintf(arg, sizeof(arg), "arg%02d", a);
				pp[a].name = strdup(arg);
				pp[a].type = BLOBMSG_TYPE_STRING;
			}
		}

		objs[i].name = t->name;
		objs[i].type = t;

		if (ubus_add_object(ctx, &objs[i])) {
			fprintf(stderr, "ubus_add_object(%s) failed\n", name);
			return 1;
		}
	}

	ubus_add_uloop(ctx);
	uloop_run();

	uloop_done();
	return 0;
}
"""

# libubox bounds blob lengths with BLOB_ATTR_LEN_MASK (0x00ffffff == 16 MiB)
BLOB_LIMIT = 0x00ffffff

# uhttpd's UH_UBUS_MAX_POST_SIZE
UH_UBUS_MAX_POST_SIZE = 65536

# how many lookup paths the fixed build accepts in one "list" request
UH_UBUS_MAX_LIST_PATHS = 512

# how many lookup paths the fixed build rejects as invalid params
OVER_MANY_PATHS = UH_UBUS_MAX_LIST_PATHS + 200


class HttpError(Exception):
    pass


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def find_ubusd():
    env = os.environ.get("UBUSD")
    if env and os.path.exists(env):
        return env
    for name in ("ubusd", "/usr/sbin/ubusd", "/usr/local/sbin/ubusd", "/sbin/ubusd"):
        path = shutil.which(name) or (name if os.path.exists(name) else None)
        if path:
            return path
    return None


def build_provider(tmpdir, verbose):
    src = os.path.join(tmpdir, "provider.c")
    exe = os.path.join(tmpdir, "provider")

    with open(src, "w") as f:
        f.write(PROVIDER_SRC)

    compilers = [c for c in (os.environ.get("CC"), "cc", "gcc", "clang") if c]
    flagsets = [os.environ.get("UBUS_CFLAGS", "").split(), [], ["-I/usr/local/include"]]
    ldflags = [os.environ.get("UBUS_LDFLAGS", "").split(), [], ["-L/usr/local/lib"]]

    for cc in dict.fromkeys(compilers):
        for cflags in flagsets:
            for ldfs in ldflags:
                cmd = [cc, "-std=gnu99", "-o", exe, src] + cflags + ["-lubus", "-lubox"] + ldfs
                if verbose:
                    print("  try: %s" % " ".join(cmd))
                try:
                    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                except (FileNotFoundError, PermissionError):
                    continue
                if p.returncode == 0:
                    return exe
                if verbose:
                    print("  %s" % p.stderr.decode(errors="replace").strip())

    return None


def decode_chunked(body):
    out = bytearray()
    while True:
        nl = body.find(b"\r\n")
        if nl < 0:
            break
        try:
            size = int(body[:nl].split(b";")[0], 16)
        except ValueError:
            break
        if size == 0:
            break
        out += body[nl + 2:nl + 2 + size]
        body = body[nl + 2 + size + 2:]
    return bytes(out)


class Client:
    def __init__(self, port):
        self.port = port

    def request(self, method, path, body=None):
        raw = ("%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n" % (method, path)).encode()

        if body is not None:
            body = body.encode()
            raw += b"Content-Type: application/json\r\nContent-Length: %d\r\n" % len(body)

        raw += b"\r\n"

        sock = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        try:
            sock.sendall(raw + (body or b""))
            sock.settimeout(120)
            data = b""
            while True:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    raise HttpError("timed out reading response")
                if not chunk:
                    break
                data += chunk
                if data.endswith(b"\r\n0\r\n\r\n"):
                    break
        finally:
            sock.close()

        head, _, rest = data.partition(b"\r\n\r\n")
        status = head.split(b"\r\n", 1)[0].decode(errors="replace")

        headers = {}
        for line in head.split(b"\r\n")[1:]:
            key, _, val = line.partition(b":")
            headers[key.decode().lower()] = val.decode().strip()

        payload = decode_chunked(rest) if headers.get("transfer-encoding", "").lower() == "chunked" else rest

        return status, payload


class Server:
    def __init__(self, uhttpd, tmpdir):
        self.uhttpd = uhttpd
        self.tmpdir = tmpdir
        self.sock = os.path.join(tmpdir, "ubus.sock")
        self.port = free_port()
        self.log = open(os.path.join(tmpdir, "uhttpd.log"), "wb")
        self.procs = []

    def start(self, ubusd, provider, objects):
        self.procs.append(subprocess.Popen([ubusd, "-s", self.sock], cwd=self.tmpdir))

        for _ in range(200):
            if os.path.exists(self.sock):
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("ubusd did not create its socket")

        self.procs.append(subprocess.Popen([provider, self.sock, str(objects)], cwd=self.tmpdir))

        env = dict(os.environ)
        env["LD_LIBRARY_PATH"] = os.path.dirname(os.path.abspath(self.uhttpd)) + os.pathsep + env.get("LD_LIBRARY_PATH", "")

        self.procs.append(subprocess.Popen(
            [self.uhttpd, "-f", "-p", "127.0.0.1:%d" % self.port, "-h", self.tmpdir,
             "-u", "/ubus", "-U", self.sock, "-t", "10", "-T", "10"],
            cwd=self.tmpdir, env=env, stdout=self.log, stderr=self.log))

    def alive(self):
        return all(p.poll() is None for p in self.procs)

    def dead_with(self):
        return [(i, p.returncode) for i, p in enumerate(self.procs) if p.returncode is not None]

    def uhttpd_output(self, limit=8):
        try:
            self.log.flush()
            with open(self.log.name, "rb") as f:
                lines = f.read().splitlines()[-limit:]
            return b" / ".join(lines).decode(errors="replace")
        except Exception:
            return ""

    def stop(self):
        for proc in reversed(self.procs):
            if proc.poll() is None:
                proc.terminate()
        for proc in self.procs:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        self.log.close()

    def wait_for_objects(self, client, wanted, timeout=60):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                _, body = client.request("GET", "/ubus/list")
                names = json.loads(body.decode(errors="replace"))
                if isinstance(names, dict) and all(w in names for w in wanted):
                    return sorted(names)
            except Exception:
                pass
            time.sleep(0.2)
        return None


def list_body(paths):
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": "list", "params": list(paths)})


def describe(body, paths):
    if paths is not None:
        return "list with %d paths" % len(paths)
    return body[:120]


def jsonrpc_error_code(payload):
    try:
        obj = json.loads(payload.decode(errors="replace"))
    except Exception:
        return None

    if isinstance(obj, dict):
        err = obj.get("error")
        if isinstance(err, dict):
            return err.get("code")
    return None


def overflow_paths(names, per_object, budget=2 * 1024 * 1024, max_paths=UH_UBUS_MAX_LIST_PATHS):
    """A set of distinct lookup paths whose combined result exceeds budget.

    Every entry is a different string, so none of them can be collapsed as a
    duplicate, and the broadest wildcards come first because they contribute
    the most response bytes per request byte.
    """
    candidates = []
    seen = set()

    for name in names:
        for i in range(1, len(name) + 1):
            path = name[:i] + "*"
            if path not in seen:
                seen.add(path)
                candidates.append(path)

    candidates.sort(key=lambda path: -sum(1 for n in names if n.startswith(path[:-1])))

    paths = []
    total = 0

    for path in candidates:
        if total > budget or len(paths) >= max_paths:
            break
        paths.append(path)
        total += per_object * sum(1 for n in names if n.startswith(path[:-1]))

    return paths, total


def run_oversize_get_case(uhttpd, ubusd, provider, tmpdir, objects, failures):
    """An unparameterized list which no longer fits has to be refused.

    Runs a second, independent uhttpd instance against an ubusd holding enough
    objects to push a single full list past the response budget.
    """
    sub = os.path.join(tmpdir, "oversize")
    os.makedirs(sub, exist_ok=True)

    server = Server(uhttpd, sub)
    try:
        server.start(ubusd, provider, objects)
        client = Client(server.port)
        last = "probe%03d" % (objects - 1)

        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                status, _ = client.request("GET", "/ubus/list/" + last)
                if "200" in status:
                    break
            except (OSError, HttpError):
                pass
            time.sleep(0.2)
        else:
            failures.append("case9: ubus objects never showed up (%s)" % server.uhttpd_output())
            return

        status, body = client.request("GET", "/ubus/list")
        try:
            code = json.loads(body.decode(errors="replace")).get("code")
        except Exception:
            code = None

        if "500" in status and code == -EFBIG and server.alive():
            print("ok   case9: GET /ubus/list over %d objects -> %s, code %s, %d bytes"
                  % (objects, status, code, len(body)))
        else:
            failures.append("case9: GET /ubus/list over %d objects -> %s, code %s, "
                            "%d bytes (alive=%s)" % (objects, status, code, len(body), server.alive()))

        status, body = client.request("GET", "/ubus/list/probe000")
        if "200" in status and b"method00" in body and server.alive():
            print("ok   case10: GET /ubus/list/probe000 -> %s after the refused list" % status)
        else:
            failures.append("case10: GET /ubus/list/probe000 -> %s (%d bytes)" % (status, len(body)))
    finally:
        server.stop()


EFBIG = 27


def run_oversize_get_case(uhttpd, ubusd, provider, tmpdir, objects, failures):
    """An unparameterized list which no longer fits has to be refused.

    Runs a second, independent uhttpd instance against a throwaway ubusd
    holding enough objects to push a single full list past the response budget.
    """
    sub = os.path.join(tmpdir, "oversize")
    os.makedirs(sub, exist_ok=True)

    server = Server(uhttpd, sub)
    try:
        server.start(ubusd, provider, objects)
        client = Client(server.port)
        last = "probe%03d" % (objects - 1)

        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                status, _ = client.request("GET", "/ubus/list/" + last)
                if "200" in status:
                    break
            except (OSError, HttpError):
                pass
            time.sleep(0.2)
        else:
            failures.append("case9: ubus objects never showed up (%s)" % server.uhttpd_output())
            return

        try:
            status, body = client.request("GET", "/ubus/list")
        except (OSError, HttpError) as e:
            status, body = "no response (%s)" % e, b""

        try:
            code = json.loads(body.decode(errors="replace")).get("code")
        except Exception:
            code = None

        if "500" in status and code == -EFBIG and server.alive():
            print("ok   case9: GET /ubus/list of %d objects -> %s, code %s, %d bytes"
                  % (objects, status, code, len(body)))
        else:
            failures.append("case9: GET /ubus/list of %d objects -> %s, code %s, "
                            "%d bytes (alive=%s)" % (objects, status, code, len(body), server.alive()))

        status, body = client.request("GET", "/ubus/list/probe000")
        if "200" in status and b"method00" in body and server.alive():
            print("ok   case10: GET /ubus/list/probe000 -> %s after the refused list" % status)
        else:
            failures.append("case10: GET /ubus/list/probe000 -> %s (%d bytes)" % (status, len(body)))
    finally:
        server.stop()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("uhttpd", help="path to the uhttpd binary")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--keep", action="store_true", help="keep the scratch directory")
    ap.add_argument("--objects", type=int, default=60, help="number of fake ubus objects")
    ap.add_argument("--oversize-objects", type=int, default=300,
                    help="object count of the oversize GET list case, 0 to skip")
    args = ap.parse_args()

    uhttpd = os.path.abspath(args.uhttpd)
    if not os.path.isfile(uhttpd):
        print("FAIL: no such binary: %s" % uhttpd)
        return 2

    ubusd = find_ubusd()
    if not ubusd:
        print("SKIP: no ubusd binary found (set UBUSD=/path/to/ubusd)")
        return 0

    tmpdir = tempfile.mkdtemp(prefix="uhttpd-ubus-list-")

    provider = build_provider(tmpdir, args.verbose)
    if not provider:
        print("SKIP: could not build the ubus object provider (needs libubus + libubox headers)")
        if not args.keep:
            shutil.rmtree(tmpdir, ignore_errors=True)
        return 0

    objects = ["probe%03d" % i for i in range(args.objects)]
    failures = []
    server = Server(uhttpd, tmpdir)

    def call(name, body, expect_codes, paths=None):
        """POST a JSON-RPC list request and check that the answer stays bounded."""
        if isinstance(expect_codes, int):
            expect_codes = (expect_codes,)
        try:
            status, payload = client.request("POST", "/ubus", body)
            code = jsonrpc_error_code(payload)
        except (OSError, HttpError) as e:
            status, payload, code = "no response (%s)" % e, b"", None

        if not server.alive():
            failures.append("%s: %s killed uhttpd (%s, exited with %s)"
                            % (name, body[:120], status, server.dead_with()))
            return status, payload, code

        if code in expect_codes:
            print("ok   %s: %s -> %s, server alive" % (name, describe(body, paths), code))
        elif code is not None:
            failures.append("%s: %s -> unexpected error %s" % (name, describe(body, paths), code))
        else:
            failures.append("%s: %s -> %s, %d bytes, no bounded error (alive=%s)"
                            % (name, describe(body, paths), status, len(payload), server.alive()))

        return status, payload, code

    try:
        server.start(ubusd, provider, args.objects)
        client = Client(server.port)

        names = server.wait_for_objects(client, objects)
        if names is None:
            print("FAIL: fake ubus objects never showed up (%s)" % server.uhttpd_output())
            return 2

        # 1. unauthenticated verbose list
        status, body = client.request("GET", "/ubus/list")
        if "200" in status and b"probe000" in body and server.alive():
            print("ok   case1: GET /ubus/list -> %s, %d bytes" % (status, len(body)))
        else:
            failures.append("case1: GET /ubus/list -> %s (%d bytes)" % (status, len(body)))

        # 2. a single wildcard lookup over JSON-RPC, without any session id
        status, body = client.request("POST", "/ubus", list_body(["*"]))
        result = None
        try:
            result = json.loads(body.decode(errors="replace")).get("result")
        except Exception:
            pass

        if isinstance(result, dict) and all(w in result for w in objects) and server.alive():
            single = len(body)
            print("ok   case2: list(['*']) -> %s, %d objects, %d bytes" % (status, len(result), single))
        else:
            single = 1
            failures.append("case2: list(['*']) -> %s, incomplete result (%s)"
                            % (status, body[:120].decode(errors="replace")))

        # 3. the request from the advisory: the same path over and over again.
        #    Repeating it must not encode the same objects over and over.
        reps = (BLOB_LIMIT + 4 * 1024 * 1024) // max(single, 1) + 10
        reps = min(reps, (UH_UBUS_MAX_POST_SIZE - 64) // 4)

        status, body = client.request("POST", "/ubus", list_body(["*"] * reps))
        duplicates = body.count(b'"probe000"')
        if not server.alive():
            failures.append("case3: list(['*']*%d) killed uhttpd (exited with %s)"
                            % (reps, server.dead_with()))
        elif duplicates > 1:
            failures.append("case3: list(['*']*%d) encoded 'probe000' %d times" % (reps, duplicates))
        else:
            print("ok   case3: list(['*']*%d) -> %s, each object encoded once, %d bytes"
                  % (reps, status, len(body)))

        # 4. distinct paths whose combined result exceeds the response budget
        per_object = max(single // max(len(objects), 1), 1)
        paths, expected = overflow_paths(names, per_object, budget=3 * 1024 * 1024)
        body = list_body(paths)

        if len(paths) < 2 or expected <= 3 * 1024 * 1024:
            failures.append("case4: cannot build an over-large result from %d lookup paths "
                            "(estimated %d bytes)" % (len(paths), expected))
        elif len(body) > UH_UBUS_MAX_POST_SIZE:
            failures.append("case4: request would be %d bytes, above the post limit" % len(body))
        else:
            print("     case4: %d distinct paths, result should be about %d bytes" % (len(paths), expected))
            call("case4", body, (-32603, -32602), paths)

        # 5. more lookup paths than a single request may name
        paths = [objects[i % len(objects)] for i in range(OVER_MANY_PATHS)]
        call("case5", list_body(paths), -32602, paths)

        # 6. error responses of the "call" path are still well formed
        call_body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "call",
                               "params": ["0" * 32, "nosuchobject", "test", {}]})
        try:
            status, body = client.request("POST", "/ubus", call_body)
            code = jsonrpc_error_code(body)
        except (OSError, HttpError) as e:
            status, body, code = "no response (%s)" % e, b"", None

        if code in (-32000, -32001, -32002) and server.alive():
            print("ok   case6: call() on a missing object -> %s" % code)
        else:
            failures.append("case6: call() on a missing object -> %s (%s)"
                            % (status, body[:120].decode(errors="replace")))

        # 7. batched requests are still answered with a JSON array
        batch = json.dumps([
            {"jsonrpc": "2.0", "id": 1, "method": "list", "params": [objects[2]]},
            {"jsonrpc": "2.0", "id": 2, "method": "call",
             "params": ["0" * 32, "nosuchobject", "test", {}]},
        ])
        try:
            status, body = client.request("POST", "/ubus", batch)
            parsed = json.loads(body.decode(errors="replace"))
            ok = isinstance(parsed, list) and len(parsed) == 2 and server.alive()
        except (OSError, HttpError, ValueError) as e:
            status, body, ok = "no response (%s)" % e, b"", False

        if ok:
            print("ok   case7: batched list+call -> %s, 2 results" % status)
        else:
            failures.append("case7: batched list+call -> %s (%s)"
                            % (status, body[:120].decode(errors="replace")))

        # 8. normal list requests are still served after the abuse above
        try:
            status, body = client.request("POST", "/ubus", list_body([objects[1]]))
            ok = "200" in status and b"method00" in body and server.alive()
        except (OSError, HttpError) as e:
            status, body, ok = "no response (%s)" % e, b"", False

        if ok:
            print("ok   case8: list(['%s']) -> %s after the abuse cases" % (objects[1], status))
        else:
            failures.append("case8: normal list after abuse -> %s (%d bytes), alive=%s"
                            % (status, len(body), server.alive()))
    finally:
        server.stop()

    if args.oversize_objects:
        run_oversize_get_case(uhttpd, ubusd, provider, tmpdir, args.oversize_objects, failures)

    if not args.keep:
        shutil.rmtree(tmpdir, ignore_errors=True)
    else:
        print("\nscratch directory kept: %s" % tmpdir)

    if failures:
        print()
        for f in failures:
            print("FAIL: %s" % f)
        return 1

    print("all ubus list encoding cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
