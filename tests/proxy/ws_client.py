#!/usr/bin/env python3
"""Drive an upgrade handshake through the proxy and check the raw tunnel."""
import socket, sys, time

port = int(sys.argv[1])
s = socket.create_connection(('127.0.0.1', port), timeout=5)
s.sendall(b'GET /strip/ws HTTP/1.1\r\n'
          b'Host: 127.0.0.1\r\n'
          b'Upgrade: websocket\r\n'
          b'Connection: Upgrade\r\n'
          b'Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n'
          b'Sec-WebSocket-Version: 13\r\n'
          # pipelined behind the handshake: must not be lost
          b'\r\nearly')

buf = b''
while b'\r\n\r\n' not in buf:
    d = s.recv(4096)
    if not d:
        print('no response'); sys.exit(1)
    buf += d

head, _, rest = buf.partition(b'\r\n\r\n')
head = head.decode()

if not head.startswith('HTTP/1.1 101 '):
    print('bad status line: %r' % head.splitlines()[0]); sys.exit(1)

low = head.lower()
for want in ('upgrade: websocket', 'connection: upgrade',
             'sec-websocket-accept: dummy'):
    if want not in low:
        print('missing handshake header %r in %r' % (want, head)); sys.exit(1)

if 'transfer-encoding' in low or 'content-length' in low:
    print('framing header injected into 101: %r' % head); sys.exit(1)


def read(n, timeout=5):
    global rest
    end = time.time() + timeout
    while len(rest) < n:
        s.settimeout(max(0.1, end - time.time()))
        try:
            d = s.recv(4096)
        except socket.timeout:
            break
        if not d:
            break
        rest += d
    out, rest = rest[:n], rest[n:]
    return out


got = read(5)
if got != b'EARLY':
    print('pipelined data lost: %r' % got); sys.exit(1)

for i in range(20):
    msg = ('msg-%d' % i).encode()
    s.sendall(msg)
    got = read(len(msg))
    if got != msg.upper():
        print('echo %d: %r' % (i, got)); sys.exit(1)

# a payload larger than the relay buffers, in both directions
big = bytes(((i % 26) + 97) for i in range(200000))
s.sendall(big)
got = read(len(big), timeout=15)
if got != big.upper():
    print('bulk transfer: got %d of %d bytes' % (len(got), len(big))); sys.exit(1)

s.close()
sys.exit(0)
