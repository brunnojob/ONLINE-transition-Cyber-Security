import concurrent.futures
import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from api.demo import handler
from guard.demo import SCENARIOS, run_demo


class DemoTests(unittest.TestCase):
    def request(self, scenario='valid'):
        return {'scenario': scenario, 'amount_minor': 10000, 'recipient': 'merchant_123'}

    def test_scenarios_execute_engine_and_verify_database(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario):
                report = run_demo(self.request(scenario))
                self.assertTrue(report['passed'])
                self.assertTrue(report['audit']['verified'])
                self.assertEqual(report['engine'], 'guard.core.Guard')
                self.assertNotIn('private_key', json.dumps(report))
                self.assertNotIn('token', report)
                self.assertEqual(report['dispatches'], 0 if scenario in ('amount', 'recipient', 'expired') else 1)

    def test_independent_visitors_have_isolated_transactions(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            reports = list(pool.map(lambda _: run_demo(self.request()), range(3)))
        self.assertEqual(len({r['transaction']['id'] for r in reports}), 3)
        self.assertTrue(all(r['passed'] and r['dispatches'] == 1 for r in reports))

    def test_invalid_requests_and_currency_precision(self):
        for value in (None, {}, {'scenario': 'valid'}, {**self.request(), 'amount_minor': True}, {**self.request(), 'amount_minor': 1.5}, {**self.request(), 'recipient': '<script>'}, {**self.request(), 'database': '/tmp/other'}):
            with self.subTest(value=value), self.assertRaises((ValueError, TypeError)):
                run_demo(value)
        report = run_demo({**self.request('amount'), 'amount_minor': 1})
        self.assertTrue(report['passed'])
        self.assertEqual(report['signed_payload'].split('\n')[5], '2')

    def test_http_contract(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f'http://127.0.0.1:{server.server_port}/api/demo'
        def post(data, content_type='application/json'):
            request = urllib.request.Request(url, data=data, headers={'Content-Type': content_type})
            try:
                with urllib.request.urlopen(request, timeout=10) as response:
                    return response.status, json.load(response)
            except urllib.error.HTTPError as response:
                return response.code, json.load(response)
        try:
            for scenario in SCENARIOS:
                status, report = post(json.dumps(self.request(scenario)).encode())
                self.assertEqual(status, 200)
                self.assertTrue(report['passed'])
            self.assertEqual(post(b'{}')[0], 400)
            self.assertEqual(post(b'not-json')[0], 400)
            self.assertEqual(post(b'{}', 'text/plain')[0], 415)
            self.assertEqual(post(b' ' * 2049)[0], 413)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
