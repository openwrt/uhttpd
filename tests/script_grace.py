#!/usr/bin/env python3
"""
Tests for the grace period between SIGTERM and SIGKILL (-g) for script
processes.

A script process is stopped when its client closes the connection before
the response and when the script timeout (-t) runs out. It gets SIGTERM
first and SIGKILL only after the grace period, so a script that ignores
SIGTERM can finish what it started, and a script that does not still dies
at once. The process keeps its script slot until it has exited.

Each case runs against CGI and, when the ucode plugin is next to the
binary, against a ucode handler. All servers run with a single script slot
(-n 1), so a slot that is never released blocks the request that checks it.

Usage: script_grace.py /path/to/uhttpd [-v]
Exit code 0 when all cases pass.
"""

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

# The script writes <name>.start, works for 2 s and writes <name>.done.
# trap.sh ignores SIGTERM, plain.sh keeps the default action.
CGI = """#!/bin/sh
PATH="@PATH@"
[ "${0##*/}" = trap.sh ] && trap '' TERM
: > "@DIR@/${QUERY_STRING}.start"
sleep 2 </dev/null >/dev/null 2>&1
: > "@DIR@/${QUERY_STRING}.done"
printf 'Status: 200 OK\\r\\nContent-Type: text/plain\\r\\n\\r\\ndone\\n'
"""

FAST = """#!/bin/sh
printf 'Status: 200 OK\\r\\nContent-Type: text/plain\\r\\n\\r\\nfast\\n'
"""

UCODE = """{%

let fs = require('fs');

global.handle_request = function(env) {
	let q = split(env.QUERY_STRING, ',');

	if (q[1] == 'trap')
		signal('SIGTERM', 'ignore');
	else if (q[1] == 'handler')
		signal('SIGTERM', function() { fs.writefile(`@DIR@/${q[0]}.term`, ''); });

	fs.writefile(`@DIR@/${q[0]}.start`, '');
	sleep(2000);
	fs.writefile(`@DIR@/${q[0]}.done`, '');
	uhttpd.send('Status: 200 OK\\r\\nContent-Type: text/plain\\r\\n\\r\\ndone\\n');
};
"""


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Server:
    def __init__(self, binary, args, verbose=False):
        self.verbose = verbose
        self.root = tempfile.mkdtemp(prefix="uhttpd-test-")
        self.marks = os.path.join(self.root, "marks")
        os.makedirs(os.path.join(self.root, "cgi-bin"))
        os.makedirs(self.marks)
        for name, text in (("trap.sh", CGI), ("plain.sh", CGI), ("fast.sh", FAST)):
            path = os.path.join(self.root, "cgi-bin", name)
            with open(path, "w") as f:
                f.write(text.replace("@DIR@", self.marks)
                        .replace("@PATH@", os.environ.get("PATH", "/bin:/usr/bin")))
            os.chmod(path, 0o755)

        cmd = [binary, "-f", "-p", "127.0.0.1:0", "-h", self.root,
               "-n", "1", "-W", "0"] + args
        if HAVE_UCODE:
            handler = os.path.join(self.root, "handler.uc")
            with open(handler, "w") as f:
                f.write(UCODE.replace("@DIR@", self.marks))
            cmd += ["-o", "/uc", "-O", handler]

        self.port = free_port()
        cmd[3] = "127.0.0.1:%d" % self.port
        self.log = os.path.join(self.root, "server.log")
        env = dict(os.environ)
        env["LD_LIBRARY_PATH"] = os.path.dirname(os.path.abspath(binary))
        self.proc = subprocess.Popen(cmd, stdout=open(self.log, "w"),
                                     stderr=subprocess.STDOUT, env=env)
        for _ in range(100):
            if self.proc.poll() is None and self.can_connect():
                return
            time.sleep(0.05)
        raise RuntimeError("server did not start:\n%s" % open(self.log).read())

    def can_connect(self):
        try:
            socket.create_connection(("127.0.0.1", self.port), 0.2).close()
            return True
        except OSError:
            return False

    def send(self, path):
        s = socket.create_connection(("127.0.0.1", self.port), 10)
        s.sendall(("GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
                   % path).encode())
        return s

    def get(self, path, timeout=10):
        s = self.send(path)
        s.settimeout(timeout)
        data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        s.close()
        return data

    def mark(self, name, kind):
        return os.path.exists(os.path.join(self.marks, "%s.%s" % (name, kind)))

    def wait_mark(self, name, kind, timeout):
        end = time.time() + timeout
        while time.time() < end:
            if self.mark(name, kind):
                return True
            time.sleep(0.05)
        return False

    def stop(self):
        self.proc.terminate()
        self.proc.wait()
        if self.verbose:
            sys.stdout.write(open(self.log).read())
        shutil.rmtree(self.root)


HAVE_UCODE = False


def url(kind, name, trap):
    mode = trap if isinstance(trap, str) else ("trap" if trap else "plain")
    if kind == "cgi":
        return "/cgi-bin/%s.sh?%s" % ("plain" if mode == "plain" else "trap", name)
    return "/uc?%s,%s" % (name, mode)


def slot_free(srv):
    # with -n 1 this only answers when no process holds the slot
    return b"fast" in srv.get("/cgi-bin/fast.sh", timeout=5)


def case_close(srv, kind, trap, expect_done):
    """Client closes before the response."""
    s = srv.send(url(kind, "c", trap))
    if not srv.wait_mark("c", "start", 3):
        return "script did not start"
    s.close()
    done = srv.wait_mark("c", "done", 3)
    if done != expect_done:
        return "done=%s, expected %s" % (done, expect_done)
    if not slot_free(srv):
        return "script slot was not released"
    return None


def case_timeout(srv, kind, trap, expect_done):
    """Script timeout (-t 1) runs out before the script is done."""
    start = time.time()
    data = srv.get(url(kind, "t", trap))
    took = time.time() - start
    ok = data.startswith(b"HTTP/1.1 200") and b"\r\n\r\n" in data and b"done\n" in data.split(b"\r\n\r\n", 1)[1]
    if ok != expect_done:
        return "complete response=%s, expected %s (%r)" % (ok, expect_done, data[:60])
    if not expect_done and took > 1.8:
        return "script was not stopped at the timeout (%.1f s)" % took
    if not slot_free(srv):
        return "script slot was not released"
    return None


def case_close_handler(srv, kind):
    """ucode: a signal() handler function runs on SIGTERM and the script goes on."""
    if kind != "ucode":
        return "skip"
    err = case_close(srv, kind, "handler", True)
    if err:
        return err
    if not srv.mark("c", "term"):
        return "the SIGTERM handler did not run"
    return None


def case_slot_held(srv, kind):
    """A script that outlives its client keeps its slot until it exits."""
    s = srv.send(url(kind, "h", True))
    if not srv.wait_mark("h", "start", 3):
        return "script did not start"
    s.close()
    data = srv.get("/cgi-bin/fast.sh")
    if b"fast" not in data:
        return "queued request was not answered"
    if not srv.mark("h", "done"):
        return "queued request ran before the terminating script exited"
    return None


CASES = [
    # name, args, function, trap, expect
    ("close, SIGTERM ignored, -g 5: script finishes", ["-g", "5"], case_close, True, True),
    ("close, default SIGTERM, -g 5: script dies", ["-g", "5"], case_close, False, False),
    ("close, SIGTERM ignored, -g 1: SIGKILL after grace", ["-g", "1"], case_close, True, False),
    ("close, SIGTERM ignored, -g 0: SIGKILL at once", ["-g", "0"], case_close, True, False),
    ("timeout, SIGTERM ignored, -g 5: response complete", ["-t", "1", "-g", "5"], case_timeout, True, True),
    ("timeout, default SIGTERM, -g 5: script dies", ["-t", "1", "-g", "5"], case_timeout, False, False),
    ("timeout, SIGTERM ignored, -g 0: SIGKILL at once", ["-t", "1", "-g", "0"], case_timeout, True, False),
]


def main():
    global HAVE_UCODE

    if len(sys.argv) < 2:
        sys.stderr.write(__doc__)
        return 2

    binary = sys.argv[1]
    verbose = "-v" in sys.argv[2:]
    HAVE_UCODE = os.path.exists(os.path.join(os.path.dirname(os.path.abspath(binary)),
                                             "uhttpd_ucode.so"))
    kinds = ["cgi"] + (["ucode"] if HAVE_UCODE else [])
    failed = 0

    runs = [(n, a, f, (t, e)) for n, a, f, t, e in CASES]
    runs.append(("close, -g 5: slot stays held until exit", ["-g", "5"], case_slot_held, None))
    runs.append(("close, SIGTERM handler function, -g 5: runs, script finishes",
                 ["-g", "5"], case_close_handler, None))

    for kind in kinds:
        for name, args, func, extra in runs:
            srv = Server(binary, args, verbose)
            try:
                err = func(srv, kind, *extra) if extra else func(srv, kind)
            finally:
                srv.stop()
            if err == "skip":
                continue
            print("%-4s %-5s %s%s" % ("FAIL" if err else "ok", kind, name,
                                      ": " + err if err else ""), flush=True)
            failed += bool(err)

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
