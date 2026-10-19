#!/usr/bin/env python3
"""Abrupt teardown cases: the server must survive all of them."""
import socket, subprocess, sys, time

port = int(sys.argv[1])


def conn():
    return socket.create_connection(('127.0.0.1', port), timeout=5)


def alive():
    out = subprocess.run(['curl', '-s', '-m', '5',
                          'http://127.0.0.1:%d/' % port],
                         capture_output=True).stdout
    return out.strip() == b'static file'


fails = []

# 1. client vanishes in the middle of a tunnel
s = conn()
s.sendall(b'GET /strip/ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n'
          b'Connection: Upgrade\r\n\r\n')
time.sleep(0.2)
s.sendall(b'some data')
s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b'\x01\x00\x00\x00\x00\x00\x00\x00')
s.close()  # RST
time.sleep(0.3)
if not alive():
    fails.append('server died after a tunnel was reset by the client')

# 2. client aborts a large download half way through
s = conn()
s.sendall(b'GET /strip/big HTTP/1.1\r\nHost: x\r\n\r\n')
s.recv(4096)
s.close()
time.sleep(0.3)
if not alive():
    fails.append('server died after an aborted download')

# 3. client sends a request body and disappears without finishing it
s = conn()
s.sendall(b'POST /strip/echo HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n')
s.sendall(b'x' * 1000)
s.close()
time.sleep(0.3)
if not alive():
    fails.append('server died after a truncated request body')

# 4. many concurrent proxied requests
socks = []
for i in range(24):
    c = conn()
    c.sendall(b'GET /strip/x HTTP/1.1\r\nHost: x\r\n\r\n')
    socks.append(c)
for c in socks:
    if b'200' not in c.recv(64):
        fails.append('concurrent request failed')
        break
    c.close()

# 5. HEAD through the proxy
s = conn()
s.sendall(b'HEAD /strip/x HTTP/1.1\r\nHost: x\r\n\r\n')
time.sleep(0.3)
s.settimeout(2)
head = s.recv(4096)
if not head.startswith(b'HTTP/1.1 200'):
    fails.append('HEAD failed: %r' % head[:40])
s.close()

if not alive():
    fails.append('server died')

for f in fails:
    print(f)
sys.exit(1 if fails else 0)
