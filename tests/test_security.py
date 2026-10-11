import base64
import concurrent.futures
import json
import os
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from guard.core import Guard, Rejected, b64, screen_url
from guard.server import serve


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.now = 1800000000
        self.guard = Guard(os.environ.get('TEST_DATABASE', self.temp.name + '/guard.db'), b'a' * 32, 'https://guard.example', lambda: self.now)
        self.key = ec.generate_private_key(ec.SECP256R1())
        public = self.key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        import uuid
        self.user = self.guard.provision('alice_' + uuid.uuid4().hex, public)
        self.other = self.guard.provision('bob_' + uuid.uuid4().hex, public)
        self.request = {'device': self.user['device'], 'recipient': 'merchant_123', 'amount_minor': 10000, 'currency': 'BRL', 'idempotency_key': 'order_1', 'source_url': 'https://guard.example/pay'}

    def tearDown(self):
        self.temp.cleanup()

    def challenge(self):
        return self.guard.challenge(self.user['token'], self.request)

    def signature(self, challenge, key=None):
        return b64((key or self.key).sign(challenge['payload'].encode(), ec.ECDSA(hashes.SHA256())))

    def reject(self, code, function, *args):
        with self.assertRaises(Rejected) as result:
            function(*args)
        self.assertEqual(result.exception.code, code)

    def test_valid_authorization_queues_exact_record(self):
        challenge = self.challenge()
        self.guard.authorize(self.user['token'], challenge['id'], self.signature(challenge))
        result = self.guard.execute(self.user['token'], challenge['id'])
        self.assertEqual(result['state'], 'QUEUED')
        self.assertEqual(len(result['record']), 116)
        self.assertEqual(result['record'][36:48], '000000010000')
        self.assertGreater(self.guard.verify_audit()['events'], 0)

    def test_execute_without_authorization(self):
        self.reject('INVALID_STATE', self.guard.execute, self.user['token'], self.challenge()['id'])

    def test_amount_tampering(self):
        challenge = self.challenge()
        challenge['payload'] = challenge['payload'].replace('\n10000\n', '\n99999\n')
        self.reject('INVALID_SIGNATURE', self.guard.authorize, self.user['token'], challenge['id'], self.signature(challenge))

    def test_recipient_tampering(self):
        challenge = self.challenge()
        challenge['payload'] = challenge['payload'].replace('merchant_123', 'attacker')
        self.reject('INVALID_SIGNATURE', self.guard.authorize, self.user['token'], challenge['id'], self.signature(challenge))

    def test_origin_tampering(self):
        challenge = self.challenge()
        challenge['payload'] = challenge['payload'].replace('https://guard.example', 'https://evil.example')
        self.reject('INVALID_SIGNATURE', self.guard.authorize, self.user['token'], challenge['id'], self.signature(challenge))

    def test_wrong_device_key(self):
        challenge = self.challenge()
        self.reject('INVALID_SIGNATURE', self.guard.authorize, self.user['token'], challenge['id'], self.signature(challenge, ec.generate_private_key(ec.SECP256R1())))

    def test_signature_replay_between_transactions(self):
        first = self.challenge()
        self.request['idempotency_key'] = 'order_2'
        second = self.challenge()
        self.reject('INVALID_SIGNATURE', self.guard.authorize, self.user['token'], second['id'], self.signature(first))

    def test_authorization_replay(self):
        challenge = self.challenge()
        signature = self.signature(challenge)
        self.guard.authorize(self.user['token'], challenge['id'], signature)
        self.reject('INVALID_STATE', self.guard.authorize, self.user['token'], challenge['id'], signature)

    def test_expired_challenge(self):
        challenge = self.challenge()
        self.now += 120
        self.reject('EXPIRED', self.guard.authorize, self.user['token'], challenge['id'], self.signature(challenge))

    def test_expired_execution(self):
        challenge = self.challenge()
        self.guard.authorize(self.user['token'], challenge['id'], self.signature(challenge))
        self.now += 120
        self.reject('EXPIRED', self.guard.execute, self.user['token'], challenge['id'])

    def test_cross_user_authorize_and_execute(self):
        challenge = self.challenge()
        self.reject('NOT_FOUND', self.guard.authorize, self.other['token'], challenge['id'], self.signature(challenge))
        self.reject('NOT_FOUND', self.guard.execute, self.other['token'], challenge['id'])

    def test_cross_user_device(self):
        self.request['device'] = self.other['device']
        self.reject('DEVICE_UNAVAILABLE', self.challenge)

    def test_idempotency_retry_and_conflict(self):
        first = self.challenge()
        self.assertEqual(first, self.challenge())
        self.request['amount_minor'] += 1
        self.reject('IDEMPOTENCY_CONFLICT', self.challenge)

    def test_failure_lockout(self):
        challenge = self.challenge()
        for _ in range(5):
            self.reject('INVALID_SIGNATURE', self.guard.authorize, self.user['token'], challenge['id'], 'AA==')
        self.reject('INVALID_STATE', self.guard.authorize, self.user['token'], challenge['id'], self.signature(challenge))

    def test_revocation_blocks_already_authorized_transfer(self):
        challenge = self.challenge()
        self.guard.authorize(self.user['token'], challenge['id'], self.signature(challenge))
        self.guard.revoke(self.user['token'], self.user['device'])
        self.reject('DEVICE_UNAVAILABLE', self.guard.execute, self.user['token'], challenge['id'])

    def test_invalid_amount_types_and_bounds(self):
        for amount in (0, -1, True, 1.1, '100', 100000001):
            self.request['amount_minor'] = amount
            self.reject('INVALID_AMOUNT', self.challenge)

    def test_untrusted_source(self):
        for url in ('http://guard.example', 'https://guard.example.evil.test', 'https://guard.example@evil.test', 'https://127.0.0.1', 'https://guard.example:444', 'https://xn--guard-abc.example'):
            self.request['source_url'] = url
            self.reject('UNTRUSTED_SOURCE', self.challenge)

    def test_injection_and_extra_fields(self):
        self.request['recipient'] = "'; DROP TABLE intents; --"
        self.reject('INVALID_RECIPIENT', self.challenge)
        self.request['recipient'] = 'merchant_123'
        self.request['skip_authorization'] = True
        self.reject('INVALID_FIELDS', self.challenge)

    def test_expired_session(self):
        self.now += 3600
        self.reject('UNAUTHENTICATED', self.challenge)

    def test_rate_limit(self):
        for index in range(30):
            self.request['idempotency_key'] = 'order_' + str(index)
            self.challenge()
        self.request['idempotency_key'] = 'order_31'
        self.reject('RATE_LIMITED', self.challenge)

    def test_invalid_session(self):
        self.reject('UNAUTHENTICATED', self.guard.challenge, 'stolen-but-invalid', self.request)

    def test_concurrent_execution_has_one_dispatch(self):
        challenge = self.challenge()
        self.guard.authorize(self.user['token'], challenge['id'], self.signature(challenge))
        def worker(_):
            try:
                return self.guard.execute(self.user['token'], challenge['id'])['state']
            except Rejected as exc:
                return exc.code
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            outcomes = list(pool.map(worker, range(24)))
        self.assertEqual(outcomes.count('QUEUED'), 1)
        with self.guard.transaction() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) AS n FROM dispatches WHERE intent=?', (challenge['id'],)).fetchone()['n'], 1)

    def test_audit_tampering_is_detected(self):
        self.challenge()
        with self.guard.transaction() as db:
            db.execute("UPDATE audit SET payload='{}' WHERE id=(SELECT MAX(id) FROM audit)")
        self.reject('AUDIT_CORRUPTED', self.guard.verify_audit)
        with self.guard.transaction() as db:
            db.execute('DELETE FROM audit')

    def test_http_flow_and_origin_rejection(self):
        server = serve(self.guard, port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f'http://127.0.0.1:{server.server_port}'
        def post(path, body, origin='https://guard.example'):
            req = urllib.request.Request(base + path, data=json.dumps(body).encode(), headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + self.user['token'], 'Origin': origin})
            try:
                with urllib.request.urlopen(req, timeout=5) as result:
                    return result.status, json.load(result)
            except urllib.error.HTTPError as error:
                return error.code, json.load(error)
        try:
            self.assertEqual(post('/v1/challenges', self.request, 'https://evil.test')[1]['error'], 'ORIGIN_DENIED')
            status, challenge = post('/v1/challenges', self.request)
            self.assertEqual(status, 201)
            self.assertEqual(post('/v1/execute', {'id': challenge['id']})[1]['error'], 'INVALID_STATE')
            self.assertEqual(post('/v1/authorize', {'id': challenge['id'], 'signature': self.signature(challenge)})[0], 200)
            self.assertEqual(post('/v1/execute', {'id': challenge['id']})[1]['state'], 'QUEUED')
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == '__main__':
    unittest.main()
