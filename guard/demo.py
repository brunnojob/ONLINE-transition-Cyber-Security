import concurrent.futures
import json
import re
import secrets
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from guard.core import Guard, Rejected, b64


SCENARIOS = ('valid', 'amount', 'recipient', 'replay', 'expired', 'concurrent')


def run_demo(body):
    if not isinstance(body, dict) or set(body) != {'scenario', 'amount_minor', 'recipient'}:
        raise ValueError('Expected scenario, amount_minor and recipient.')
    scenario, amount, recipient = body['scenario'], body['amount_minor'], body['recipient']
    if scenario not in SCENARIOS:
        raise ValueError('Unknown scenario.')
    if type(amount) is not int or not 1 <= amount <= 99_999_999:
        raise ValueError('Amount must be integer cents between 1 and 99999999.')
    if not isinstance(recipient, str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', recipient):
        raise ValueError('Recipient must contain 1–64 letters, digits, underscores or hyphens.')
    started = time.perf_counter()
    now = [int(time.time())]
    steps = []
    with tempfile.TemporaryDirectory(prefix='guard-demo-') as directory:
        guard = Guard(str(Path(directory) / 'demo.db'), secrets.token_bytes(32), 'https://demo.transaction-guard.test', lambda: now[0])
        key = ec.generate_private_key(ec.SECP256R1())
        public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        user = guard.provision('demo_user', public)
        request = {'device': user['device'], 'recipient': recipient, 'amount_minor': amount, 'currency': 'BRL', 'idempotency_key': 'demo_order', 'source_url': guard.origin + '/pay'}
        challenge = guard.challenge(user['token'], request)
        steps.append({'action': 'CHALLENGE_CREATED', 'outcome': 'PENDING', 'detail': 'Desafio criado pelo motor Python com nonce e validade de 120 segundos.'})
        payload = challenge['payload']
        if scenario == 'amount':
            fields = payload.split('\n')
            fields[5] = str(amount + 1)
            payload = '\n'.join(fields)
        elif scenario == 'recipient':
            fields = payload.split('\n')
            fields[4] = 'changed_recipient' if recipient != 'changed_recipient' else 'other_recipient'
            payload = '\n'.join(fields)
        signature = b64(key.sign(payload.encode(), ec.ECDSA(hashes.SHA256())))
        steps.append({'action': 'SIGNED', 'outcome': 'ECDSA_P256', 'detail': 'Assinatura de teste gerada no servidor com chave efêmera.'})
        if scenario == 'expired':
            now[0] += 121
            steps.append({'action': 'ADVANCE_TEST_CLOCK', 'outcome': '+121s', 'detail': 'O relógio injetado avança sem esperar nem alterar o relógio do servidor.'})
        rejection = None
        try:
            guard.authorize(user['token'], challenge['id'], signature)
            steps.append({'action': 'AUTHORIZE', 'outcome': 'AUTHORIZED', 'detail': 'A assinatura corresponde aos dados originais.'})
            if scenario == 'concurrent':
                def dispatch(_):
                    try:
                        return guard.execute(user['token'], challenge['id'])['state']
                    except Rejected as exc:
                        return exc.code
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                    outcomes = list(pool.map(dispatch, range(8)))
                steps.append({'action': 'CONCURRENT_DISPATCH', 'outcome': f'{outcomes.count("QUEUED")} QUEUED / {len(outcomes) - outcomes.count("QUEUED")} REJECTED', 'detail': 'Oito chamadas reais ao mesmo banco SQLite; apenas uma deve entrar na fila.'})
            else:
                result = guard.execute(user['token'], challenge['id'])
                steps.append({'action': 'EXECUTE', 'outcome': result['state'], 'detail': 'Uma instrução foi inserida na fila local; nenhum pagamento foi realizado.'})
                if scenario == 'replay':
                    guard.authorize(user['token'], challenge['id'], signature)
        except Rejected as exc:
            rejection = exc.code
            steps.append({'action': 'REJECTED', 'outcome': rejection, 'detail': 'O motor rejeitou a operação; o estado do banco foi consultado após a tentativa.'})
        audit = guard.verify_audit()
        with guard.transaction() as db:
            state = db.execute('SELECT state FROM intents WHERE id=?', (challenge['id'],)).fetchone()['state']
            dispatches = db.execute('SELECT COUNT(*) AS n FROM dispatches').fetchone()['n']
            events = [json.loads(row['payload']) for row in db.execute('SELECT payload FROM audit ORDER BY id').fetchall()]
        expected = {'valid': (None, 'QUEUED', 1), 'amount': ('INVALID_SIGNATURE', 'PENDING', 0), 'recipient': ('INVALID_SIGNATURE', 'PENDING', 0), 'replay': ('INVALID_STATE', 'QUEUED', 1), 'expired': ('EXPIRED', 'EXPIRED', 0), 'concurrent': (None, 'QUEUED', 1)}[scenario]
        passed = (rejection, state, dispatches) == expected
        if scenario == 'concurrent':
            passed = passed and outcomes.count('QUEUED') == 1 and outcomes.count('INVALID_STATE') == 7
        return {'scenario': scenario, 'passed': passed, 'state': state, 'dispatches': dispatches, 'rejection': rejection, 'steps': steps, 'transaction': {'id': challenge['id'], 'recipient': recipient, 'amount_minor': amount, 'currency': 'BRL'}, 'signed_payload': payload, 'original_payload_sha256': challenge['payload_sha256'], 'audit': {'verified': True, 'head': audit['head'], 'events': events}, 'elapsed_ms': round((time.perf_counter() - started) * 1000, 2), 'engine': 'guard.core.Guard', 'storage': 'isolated temporary SQLite; deleted after request', 'settlement': 'not-connected'}
