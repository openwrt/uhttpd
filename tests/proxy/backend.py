#!/usr/bin/env python3
"""Minimal HTTP backend used to exercise the uhttpd reverse proxy.

Every endpoint answers on any path, so the same backend can be reached
through a pass-through prefix and through a rewriting one.
"""
import socketserver, sys, time


class Handler(socketserver.BaseRequestHandler):
    def readline(self, f):
        return f.readline().decode('latin1').rstrip('\r\n')

    def handle(self):
        f = self.request.makefile('rb')
        while True:
            line = self.readline(f)
            if not line:
                return

            method, path, ver = line.split(' ')
            hdr = {}
            while True:
                h = self.readline(f)
                if not h:
                    break
                k, _, v = h.partition(':')
                hdr[k.strip().lower()] = v.strip()

            base = path.split('?')[0]
            body = b''

            if base.endswith('/slowecho'):
                # read the body in small steps, so that the proxy has to
                # apply backpressure towards the client
                n = int(hdr['content-length'])
                while len(body) < n:
                    body += f.read(min(4096, n - len(body)))
                    time.sleep(0.002)
            elif 'content-length' in hdr:
                body = f.read(int(hdr['content-length']))
            elif hdr.get('transfer-encoding') == 'chunked':
                while True:
                    n = int(self.readline(f), 16)
                    if n == 0:
                        self.readline(f)
                        break
                    body += f.read(n)
                    self.readline(f)

            if not self.dispatch(method, path, base, ver, hdr, body):
                return

    def send(self, data):
        self.request.sendall(data if isinstance(data, bytes) else data.encode())

    def reply(self, body, status='200 OK'):
        self.send('HTTP/1.1 %s\r\nContent-Type: text/plain\r\n'
                  'Content-Length: %d\r\n\r\n' % (status, len(body)))
        self.send(body)

    def dispatch(self, method, path, base, ver, hdr, body):
        """Returns whether the connection may be reused."""
        if base.endswith('/ws') and hdr.get('upgrade', '').lower() == 'websocket':
            self.send('HTTP/1.1 101 Switching Protocols\r\n'
                      'Upgrade: websocket\r\n'
                      'Connection: Upgrade\r\n'
                      'Sec-WebSocket-Accept: dummy\r\n\r\n')
            self.tunnel()
            return False

        if base.endswith('/chunked'):
            self.send('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n'
                      'Transfer-Encoding: chunked\r\n\r\n')
            for part in (b'alpha', b'beta', b'gamma'):
                self.send(b'%x\r\n%s\r\n' % (len(part), part))
            self.send(b'0\r\n\r\n')
            return False

        if base.endswith('/noframing'):
            # neither Content-Length nor chunked: delimited by the close
            self.send('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n'
                      'delimited-by-close')
            return False

        if base.endswith('/big'):
            blob = (b'0123456789abcdef' * 64) * 2048   # 2 MiB
            self.send('HTTP/1.1 200 OK\r\n'
                      'Content-Type: application/octet-stream\r\n'
                      'Content-Length: %d\r\n\r\n' % len(blob))
            self.send(blob)
            return False

        if base.endswith('/echo') or base.endswith('/slowecho'):
            self.reply(body)
            return False

        if base.endswith('/204'):
            self.send('HTTP/1.1 204 No Content\r\n\r\n')
            return False

        # default: report what the backend actually received
        seen = '%s %s %s\n' % (method, path, ver)
        for k in sorted(hdr):
            seen += '%s: %s\n' % (k, hdr[k])
        self.reply(seen.encode())
        return False

    def tunnel(self):
        """Echo everything back uppercased until the peer goes away."""
        while True:
            try:
                data = self.request.recv(4096)
            except OSError:
                return
            if not data:
                return
            self.send(data.upper())


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        # the proxy drops backend connections when a client goes away, which
        # is a normal part of the teardown tests
        pass


if __name__ == '__main__':
    Server(('127.0.0.1', int(sys.argv[1])), Handler).serve_forever()
