import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .core import Guard, Rejected, screen_url


def serve(guard, host='127.0.0.1', port=8080):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def reply(self, status, value):
            data = json.dumps(value).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == '/health':
                return self.reply(200, {'status': 'ready', 'settlement': 'not-connected'})
            self.reply(404, {'error': 'NOT_FOUND'})

        def do_POST(self):
            try:
                origin = self.headers.get('Origin')
                if origin and origin != guard.origin:
                    raise Rejected('ORIGIN_DENIED')
                if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Type') != 'application/json':
                    raise Rejected('INVALID_CONTENT_TYPE')
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 8192:
                    raise Rejected('INVALID_BODY_SIZE')
                self.connection.settimeout(5)
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise Rejected('INVALID_BODY_SIZE')
                def unique(pairs):
                    result = {}
                    for key, value in pairs:
                        if key in result:
                            raise Rejected('DUPLICATE_FIELD')
                        result[key] = value
                    return result
                body = json.loads(raw, object_pairs_hook=unique)
                if not isinstance(body, dict):
                    raise Rejected('INVALID_BODY')
                auth = self.headers.get('Authorization', '')
                if not auth.startswith('Bearer '):
                    raise Rejected('UNAUTHENTICATED')
                token = auth[7:]
                with guard.transaction() as db:
                    guard.authenticate(db, token)
                if self.path == '/v1/challenges':
                    return self.reply(201, guard.challenge(token, body))
                if self.path == '/v1/authorize' and set(body) == {'id', 'signature'}:
                    return self.reply(200, guard.authorize(token, body['id'], body['signature']))
                if self.path == '/v1/execute' and set(body) == {'id'}:
                    return self.reply(200, guard.execute(token, body['id']))
                if self.path == '/v1/revoke' and set(body) == {'device'}:
                    return self.reply(200, guard.revoke(token, body['device']))
                if self.path == '/v1/screen-url' and set(body) == {'url'}:
                    from urllib.parse import urlsplit
                    return self.reply(200, screen_url(body['url'], {urlsplit(guard.origin).hostname}))
                raise Rejected('INVALID_ROUTE_OR_FIELDS')
            except Rejected as exc:
                self.reply(401 if exc.code == 'UNAUTHENTICATED' else 409, {'error': exc.code})
            except (ValueError, TypeError, KeyError):
                self.reply(400, {'error': 'INVALID_INPUT'})
            except Exception:
                self.reply(503, {'error': 'SERVICE_UNAVAILABLE'})

    return ThreadingHTTPServer((host, port), Handler)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['serve', 'provision', 'audit'])
    parser.add_argument('--owner')
    parser.add_argument('--public-key')
    args = parser.parse_args()
    key = bytes.fromhex(os.environ['GUARD_AUDIT_KEY'])
    guard = Guard(os.environ['GUARD_DATABASE'], key, os.environ['GUARD_ORIGIN'])
    if args.command == 'provision':
        print(json.dumps(guard.provision(args.owner, Path(args.public_key).read_text())))
    elif args.command == 'audit':
        print(json.dumps(guard.verify_audit()))
    else:
        serve(guard).serve_forever()


if __name__ == '__main__':
    main()
