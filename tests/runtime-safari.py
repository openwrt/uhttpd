#!/usr/bin/env python3
"""Local HTTP smoke test: python3 tests/runtime-safari.py /path/to/uhttpd.
Uses a temporary document root and localhost only; never contacts a modem.
This tests real request parsing/connection reuse, not TLS or browser rendering.
"""
import http.client
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

PREFIX = 'Mozilla/5.0 (iPhone; CPU iPhone OS 27_0_0 like Mac OS X) AppleWebKit/605.1.15 '
SUFFIX = ' Mobile/15E148 Safari/604.1'
MODERN = PREFIX + 'Version/27.0' + SUFFIX

with tempfile.TemporaryDirectory() as directory:
    (Path(directory) / 'asset.txt').write_text('keepalive-check\n')
    # Reserve a free loopback port; retrying the test is safe if another process
    # takes it between release and uhttpd startup.
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    server = subprocess.Popen([sys.argv[1], '-f', '-h', directory,
                               '-p', f'127.0.0.1:{port}', '-k', '2'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for attempt in range(50):
            if server.poll() is not None:
                raise RuntimeError(server.stderr.read().decode())
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError('uhttpd did not listen')

        def request(conn, ua, close, headers=None, method='GET', status=200):
            conn.request(method, '/asset.txt', headers={'User-Agent': ua, **(headers or {})})
            sock = conn.sock
            response = conn.getresponse()
            body = response.read()
            assert response.status == status, response.status
            assert response.will_close == close, (ua, response.getheader('Connection'))
            if status == 200:
                assert body == b'keepalive-check\n'
            return sock, response

        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=4)
        sock, first = request(conn, MODERN, False)
        sock2, _ = request(conn, MODERN, False)
        assert sock is sock2
        etag = first.getheader('ETag')
        assert etag
        sock3, _ = request(conn, MODERN, False, {'If-None-Match': etag}, status=304)
        assert sock3 is sock
        request(conn, MODERN, True, {'Connection': 'close'})
        conn.close()
        for ua, closes in [(PREFIX+'Version/26.9'+SUFFIX, True),
                           (PREFIX+'Version/28.0'+SUFFIX, False),
                           (PREFIX+'CriOS/153.0.8010.24'+SUFFIX, True),
                           (PREFIX+'Chrome/153.0'+SUFFIX, False)]:
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=4)
            request(conn, ua, closes)
            conn.close()
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=4)
        conn._http_vsn = 10
        conn._http_vsn_str = 'HTTP/1.0'
        request(conn, MODERN, True)
        conn.close()
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=4)
        request(conn, 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)', True, method='POST')
        conn.close()
        print('Passed live HTTP socket reuse, ETag 304, version gates, explicit close, HTTP/1.0 and IE POST checks')
    finally:
        server.terminate()
        server.communicate(timeout=5)
