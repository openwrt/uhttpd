#!/usr/bin/env python3
"""
Regression tests for the chunked request body parser (client_poll_post_data()).

Covers the out-of-bounds read / ustream_consume() abort() reported by
Guy Godfroy: a chunked body whose chunk terminator CRLF arrives split over
several packets made the parser search - and then consume - bytes beyond the
valid data of the ustream read buffer, which aborted the whole server.

Also covers the framing the parser has to get right around that: chunk size
lines split across packets, chunk extensions (RFC 9112 7.1.1), trailer
sections, malformed size lines and keep-alive reuse of the connection.

Usage: chunked_body.py /path/to/uhttpd [-v]
Exit code 0 when all cases pass.
"""

import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import time

CGI = """#!/bin/sh
cat | wc -c | tr -d ' \\n' > "@BODY_DIR@/${QUERY_STRING}"
printf 'Status: 200 OK\\r\\nContent-Type: text/plain\\r\\n\\r\\nok\\r\\n'
"""

PATH = "/cgi-bin/dump.sh"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Server:
    def __init__(self, binary, verbose=False):
        self.verbose = verbose
        self.root = tempfile.mkdtemp(prefix="uhttpd-test-")
        self.bodies = os.path.join(self.root, "bodies")
        os.makedirs(os.path.join(self.root, "cgi-bin"))
        os.makedirs(self.bodies)
        cgi = os.path.join(self.root, "cgi-bin", "dump.sh")
        with open(cgi, "w") as f:
            f.write(CGI.replace("@BODY_DIR@", self.bodies))
        os.chmod(cgi, 0o755)

        self.port = free_port()
        self.log = os.path.join(self.root, "server.log")
        self.proc = subprocess.Popen(
            [binary, "-f", "-p", "127.0.0.1:%d" % self.port, "-h", self.root,
             "-T", "2", "-t", "3"],
            stdout=open(self.log, "w"),
            stderr=subprocess.STDOUT,
        )
        for _ in range(100):
            if self.alive() and self.can_connect():
                return
            time.sleep(0.05)
        raise RuntimeError("server did not start:\n%s" % open(self.log).read())

    def can_connect(self):
        try:
            s = socket.create_connection(("127.0.0.1", self.port), timeout=1)
            s.close()
            return True
        except OSError:
            return False

    def alive(self):
        return self.proc.poll() is None

    def body_size(self, name):
        path = os.path.join(self.bodies, name)
        for _ in range(50):
            try:
                with open(path) as f:
                    return int(f.read().strip())
            except (FileNotFoundError, ValueError):
                time.sleep(0.05)
        return None

    def connect(self):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=4)
        s.settimeout(4)
        return s

    def stop(self):
        self.proc.kill()
        self.proc.wait()
        shutil.rmtree(self.root, ignore_errors=True)


class Case:
    def __init__(self, name, frags, body=None, status=None, note="", close_after_send=False):
        self.name = name
        self.frags = frags   # list of (delay, bytes); None means "send the request header"
        self.body = body     # expected bytes received by the CGI, or None
        self.status = status # expected response status code, or None
        self.note = note
        # close our side right after sending instead of waiting for a response:
        # for framing that can never be completed, waiting would leave a request
        # with a live CGI around and disturb the following case
        self.close_after_send = close_after_send


def header(name, body_extra=b""):
    return (b"POST " + (PATH + "?" + name).encode() + b" HTTP/1.1\r\n"
            b"Host: localhost\r\nConnection: keep-alive\r\n"
            b"Transfer-Encoding: chunked\r\n" + body_extra + b"\r\n")


def read_response(s):
    """Read the status line; returns (status_code or None, closed_by_server)"""
    data = b""
    try:
        while b"\r\n" not in data:
            chunk = s.recv(4096)
            if not chunk:
                return (parse_status(data), True)
            data += chunk
    except socket.timeout:
        return (None, False)

    return (parse_status(data), False)


def parse_status(data):
    try:
        return int(data.split(b" ", 2)[1])
    except (IndexError, ValueError):
        return None


def run_case(srv, case):
    errors = []
    s = srv.connect()
    try:
        for delay, frag in case.frags:
            try:
                s.sendall(header(case.name) if frag is None else frag)
            except OSError:
                errors.append("send failed (connection closed early)")
                break
            if delay:
                time.sleep(delay)

        if case.close_after_send:
            s.close()
            if not srv.alive():
                errors.append("uhttpd died (signal %d)" % srv.proc.returncode)
            return errors

        status, closed = read_response(s)

        if case.status is not None and status != case.status:
            if closed:
                errors.append("connection closed without a response, expected %d" % case.status)
            elif status is None:
                errors.append("no response within timeout (parser stalled?)")
            else:
                errors.append("status %s, expected %d" % (status, case.status))
        elif case.status is None and status is None and not closed:
            errors.append("no response within timeout (parser stalled?)")

        if case.body is not None:
            got = srv.body_size(case.name)
            if got != case.body:
                errors.append("body %s bytes, expected %d" % (got, case.body))
    finally:
        s.close()

    if not srv.alive():
        errors.append("uhttpd died (signal %d)" % srv.proc.returncode)

    return errors


def build_cases():
    cases = []

    # baseline: a single, well formed chunked body
    cases.append(Case("simple", [(0, None), (0, b"5\r\nhello\r\n0\r\n\r\n")],
                      body=5, status=200))

    # chunk data split into several packets
    frags = [(0, None)]
    body = b"a\r\n" + b"abcdefghij" + b"\r\n0\r\n\r\n"
    for i in range(0, len(body), 4):
        frags.append((0.05, body[i:i + 4]))
    cases.append(Case("fragmented", frags, body=10, status=200))

    # a chunk-size line split across packets: the parser must wait for the
    # rest of it instead of acting on whatever follows in the buffer
    cases.append(Case("split-size-line",
                      [(0, None), (0, b"a\r\nabcdefghij"), (0.4, b"\r\n0"),
                       (0.4, b"\r\n\r\n")],
                      body=10, status=200))

    # the reported trigger, form 1: a chunk that ends with a lone CR, so the
    # two bytes the parser skips are not buffered yet
    d = b"zzzzzzzz\r\n" * 300
    cases.append(Case("report-form1",
                      [(0, None), (0, b"%x\r\n" % len(d) + d),
                       (0.4, b"\r\n64\r\n" + b"a" * 100 + b"\r"),
                       (0.4, b"\n0\r\n\r\n")],
                      body=len(d) + 100, status=200))

    # the same, sent exactly as in the report: header, size line and chunk data
    # in one write, so the buffer layout matches the one the reporter had
    cases.append(Case("report-form1-exact",
                      [(0, b"POST " + PATH.encode() + b" HTTP/1.1\r\nHost: x\r\n"
                          b"Transfer-Encoding: chunked\r\n\r\n%x\r\n" % len(d) + d),
                       (0.4, b"\r\n64\r\n" + b"a" * 100 + b"\r"),
                       (0.4, b"\n0\r\n\r\n")],
                      body=None, status=200,
                      note="crash reproducer from the report"))

    # the reported trigger, form 2: a previous request on the same keep-alive
    # connection leaves a CRLF in the buffer, then a chunk ends with a lone CR
    s1 = b"POST " + (PATH + "?form2-pre").encode() + b" HTTP/1.1\r\nHost: localhost\r\n" \
         b"Content-Length: 8\r\nConnection: keep-alive\r\n\r\nAA\r\nBB\r\n"
    cases.append(Case("report-form2",
                      [(0, s1), (0.3, None),
                       (0, b"6\r\nabcdef\r"), (0.4, b"\n5\r\ngrqzy\r\n0\r\n\r\n")],
                      body=11, status=200))

    # chunk terminator CRLF itself split over two packets
    cases.append(Case("split-chunk-terminator",
                      [(0, None), (0, b"3\r\nabc\r"), (0.4, b"\n"),
                       (0.4, b"5\r\n12345\r\n0\r\n\r\n")],
                      body=8, status=200))

    # chunk extensions, RFC 9112 7.1.1: they must be skipped, not rejected
    cases.append(Case("chunk-ext",
                      [(0, None), (0, b"7;name=value\r\nabcdefg\r\n0\r\n\r\n")],
                      body=7, status=200))
    cases.append(Case("chunk-ext-ietf-tchar",
                      [(0, None), (0, b"6;a=b-c.d!e\r\nabcdef\r\n0\r\n\r\n")],
                      body=6, status=200))
    cases.append(Case("chunk-ext-quoted-string",
                      [(0, None), (0, b'5 ;a="x y";b\r\n12345\r\n0\r\n\r\n')],
                      body=5, status=200))
    cases.append(Case("chunk-ext-unterminated-quote",
                      [(0, None), (0, b'5;a="x\r\n12345\r\n0\r\n\r\n')],
                      body=None, status=None,
                      note="malformed extension, connection must just close"))

    # uppercase hex sizes
    cases.append(Case("uppercase-hex",
                      [(0, None), (0, b"A\r\n0123456789\r\n0\r\n\r\n")],
                      body=10, status=200))

    # trailer section after the terminal chunk must not be parsed as the
    # next request: the connection has to stay usable afterwards
    cases.append(Case("trailer-then-next-request",
                      [(0, None),
                       (0, b"3\r\nabc\r\n0\r\nX-Trailer: 1\r\nAnother: 2\r\n\r\n"),
                       (0.2, None), (0, b"4\r\nwxyz\r\n0\r\n\r\n")],
                      body=4, status=200))

    # malformed framing must terminate the connection, not the server
    cases.append(Case("bad-size-line",
                      [(0, None), (0, b"3\r\nabc\r\nzz\r\n0\r\n\r\n")],
                      body=None, status=None))
    cases.append(Case("bad-chunk-terminator",
                      [(0, None), (0, b"3\r\nabcX"), (0.3, b"\r\n0\r\n\r\n")],
                      body=None, status=None))
    cases.append(Case("lone-cr-then-garbage",
                      [(0, None), (0, b"3\r\nabc\r"), (0.3, b"X\r\n0\r\n\r\n")],
                      body=None, status=None))
    cases.append(Case("oversized-size-line",
                      [(0, None), (0, b"f" * 5000 + b"\r\n"), (0.3, b"x" * 100)],
                      body=None, status=None, close_after_send=True,
                      note="buffer-filling size line: must not wedge the server"))

    # deterministic randomized fragmentation of well formed bodies
    for seed in (1, 2, 3):
        rnd = random.Random(seed)
        chunks, body = [], b""
        for _ in range(6):
            n = rnd.choice([1, 7, 200, 1500, 4000])
            data = bytes(rnd.choice([97, 98, 99]) for _ in range(n))
            chunks.append(b"%x\r\n" % n + data + b"\r\n")
            body += data
        framed = b"".join(chunks) + b"0\r\n\r\n"
        frags, pos = [], 0
        while pos < len(framed):
            n = rnd.randint(1, len(framed) - pos)
            frags.append((0.01, framed[pos:pos + n]))
            pos += n
        frags.insert(0, (0, None))
        cases.append(Case("random-%d" % seed, frags, body=len(body), status=200))

    return cases


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    binary = os.path.abspath(sys.argv[1])
    verbose = "-v" in sys.argv

    srv = Server(binary)
    cases = build_cases()
    failed = 0
    try:
        for case in cases:
            errors = run_case(srv, case)
            failed += bool(errors)
            if errors:
                print("FAIL %-28s %s" % (case.name, "; ".join(errors)))
            elif verbose:
                print("ok   %-28s %s" % (case.name, case.note))
            if not srv.alive():
                print("uhttpd terminated with signal %d, aborting test run"
                      % srv.proc.returncode)
                break
    finally:
        log = open(srv.log).read()
        srv.stop()

    if log.strip():
        print("--- server output ---")
        print(log.rstrip())

    print("%d case(s), %d failed" % (len(cases), failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
