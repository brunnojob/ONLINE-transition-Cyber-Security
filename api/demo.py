import json
import logging
import sys
from http.server import BaseHTTPRequestHandler
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from guard.demo import run_demo


class handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def reply(self, status, value):
        data = json.dumps(value).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.reply(200, {'status': 'ready', 'engine': 'guard.core.Guard', 'settlement': 'not-connected'})

    def do_POST(self):
        try:
            if self.headers.get('Content-Type', '').split(';')[0].strip() != 'application/json' or self.headers.get('Transfer-Encoding'):
                return self.reply(415, {'error': 'JSON_REQUIRED'})
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 2048:
                return self.reply(413, {'error': 'BODY_TOO_LARGE'})
            self.connection.settimeout(10)
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError('Incomplete body.')
            result = run_demo(json.loads(raw))
            self.reply(200 if result['passed'] else 500, result)
        except (ValueError, TypeError, KeyError):
            self.reply(400, {'error': 'INVALID_INPUT'})
        except Exception:
            logging.exception('Demo execution failed')
            self.reply(503, {'error': 'DEMO_UNAVAILABLE'})
