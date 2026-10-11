import argparse
import json
import os
import platform
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from guard.core import Guard


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='evidence/proof.json')
    parser.add_argument('--required-clients', default='java,cobol')
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.discover('tests', pattern='test_*.py')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    proof = {'schema': 1, 'generated_at_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'python': platform.python_version(), 'database': 'postgresql' if os.environ.get('TEST_DATABASE') else 'sqlite', 'security_tests': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors), 'interop': {}, 'settlement': 'not-connected'}
    required = set(filter(None, args.required_clients.split(',')))
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        key = ec.generate_private_key(ec.SECP256R1())
        private = root / 'key.der'
        private.write_bytes(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        private.chmod(0o600)
        guard = Guard(os.environ.get('TEST_DATABASE', str(root / 'proof.db')), b'a' * 32, 'https://guard.example')
        user = guard.provision('proof_' + str(time.time_ns()), key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode())
        commands = {
            'java': ['java', 'clients/java/GuardSigner.java'],
            'kotlin': ['java', '-cp', 'build/kotlin.jar', 'GuardSigner'],
            'swift': ['build/swift-signer'],
        }
        if shutil.which('kotlinc'):
            Path('build').mkdir(exist_ok=True)
            subprocess.run(['kotlinc', 'clients/kotlin/GuardSigner.kt', '-include-runtime', '-d', 'build/kotlin.jar', '-jvm-target', '1.8'], check=True)
        if platform.system() == 'Darwin' and shutil.which('swiftc'):
            Path('build').mkdir(exist_ok=True)
            subprocess.run(['swiftc', 'clients/swift/Sources/GuardSigner/main.swift', '-o', 'build/swift-signer'], check=True)
        record = None
        for client, command in commands.items():
            available = shutil.which('java') if client == 'java' else Path('build/kotlin.jar' if client == 'kotlin' else 'build/swift-signer').exists()
            if not available:
                proof['interop'][client] = 'not-executed'
                if client in required:
                    raise RuntimeError(client + ' is required but unavailable')
                continue
            challenge = guard.challenge(user['token'], {'device': user['device'], 'recipient': 'merchant_123', 'amount_minor': 10000, 'currency': 'BRL', 'idempotency_key': client, 'source_url': 'https://guard.example/pay'})
            payload = root / 'payload.txt'
            payload.write_text(challenge['payload'])
            signed = subprocess.run(command + [str(private), str(payload), guard.origin], capture_output=True, text=True, check=True).stdout.strip()
            guard.authorize(user['token'], challenge['id'], signed)
            record = guard.execute(user['token'], challenge['id'])['record']
            invalid = subprocess.run(command + [str(private), str(payload), 'https://evil.example'], capture_output=True)
            if invalid.returncode == 0:
                raise RuntimeError(client + ' accepted an untrusted origin')
            proof['interop'][client] = 'signature-verified-and-origin-rejected'
        if shutil.which('cobc'):
            Path('build').mkdir(exist_ok=True)
            subprocess.run(['cobc', '-x', '-free', 'mainframe/guard.cob', '-o', 'build/guard-gate'], check=True)
            if record is None:
                raise RuntimeError('No verified dispatch to feed COBOL')
            accepted = subprocess.run(['build/guard-gate'], input=record + '\n', text=True, capture_output=True, check=True)
            invalid_records = [record[:-1] + 'N', record[:36] + '000000000000' + record[48:], record[:48] + 'XXX' + record[51:], 'invalid']
            for invalid_record in invalid_records:
                rejected = subprocess.run(['build/guard-gate'], input=invalid_record + '\n', text=True, capture_output=True)
                if rejected.returncode == 0:
                    raise RuntimeError('COBOL accepted invalid record')
            proof['interop']['cobol'] = {'valid_record': accepted.stdout.strip(), 'invalid_records_rejected': len(invalid_records)}
        else:
            proof['interop']['cobol'] = 'not-executed'
            if 'cobol' in required:
                raise RuntimeError('COBOL is required but unavailable')
        proof['audit'] = guard.verify_audit()
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps(proof, indent=2))


if __name__ == '__main__':
    main()
