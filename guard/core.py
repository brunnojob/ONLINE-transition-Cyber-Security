import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class Rejected(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def b64(value):
    return base64.b64encode(value).decode()


def screen_url(value, allowed_hosts):
    if not isinstance(value, str) or len(value) > 2048:
        raise Rejected('INVALID_URL')
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ''
        port = parsed.port
    except ValueError:
        raise Rejected('INVALID_URL')
    reasons = []
    if parsed.scheme != 'https':
        reasons.append('HTTPS_REQUIRED')
    if parsed.username is not None or parsed.password is not None:
        reasons.append('EMBEDDED_CREDENTIALS')
    if port not in (None, 443):
        reasons.append('NONSTANDARD_PORT')
    if not host or not host.isascii() or 'xn--' in host:
        reasons.append('AMBIGUOUS_HOST')
    try:
        ipaddress.ip_address(host)
        reasons.append('IP_LITERAL')
    except ValueError:
        pass
    if host not in allowed_hosts:
        reasons.append('UNTRUSTED_HOST')
    if '\\' in value or any(ord(c) < 33 for c in value):
        reasons.append('AMBIGUOUS_URL')
    return {'allowed': not reasons, 'host': host, 'reasons': reasons}


class Connection:
    def __init__(self, raw, postgres):
        self.raw = raw
        self.postgres = postgres

    def execute(self, sql, values=()):
        return self.raw.execute(sql.replace('?', '%s') if self.postgres else sql, values)


class Guard:
    def __init__(self, database, audit_key, origin, clock=time.time):
        if len(audit_key) < 32:
            raise ValueError('Audit key must contain at least 32 bytes')
        parsed = urlsplit(origin)
        if parsed.scheme != 'https' or parsed.path or parsed.query or parsed.fragment or parsed.username or not parsed.hostname:
            raise ValueError('Origin must be an HTTPS origin without a path')
        self.database = database
        self.audit_key = audit_key
        self.origin = origin
        self.clock = clock
        self.postgres = database.startswith(('postgresql://', 'postgres://'))
        self.initialize()

    def connect(self):
        if self.postgres:
            import psycopg
            from psycopg.rows import dict_row
            return Connection(psycopg.connect(self.database, row_factory=dict_row, options='-c search_path=txguard,pg_catalog'), True)
        raw = sqlite3.connect(self.database, timeout=30, isolation_level=None)
        raw.row_factory = sqlite3.Row
        raw.execute('PRAGMA foreign_keys=ON')
        return Connection(raw, False)

    def initialize(self):
        with self.transaction() as db:
            if self.postgres:
                db.execute('CREATE SCHEMA IF NOT EXISTS txguard')
            statements = [
                'CREATE TABLE IF NOT EXISTS principals (id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, expires BIGINT NOT NULL)',
                'CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, owner TEXT NOT NULL REFERENCES principals(id), public_key TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)',
                'CREATE TABLE IF NOT EXISTS intents (id TEXT PRIMARY KEY, owner TEXT NOT NULL REFERENCES principals(id), device TEXT NOT NULL REFERENCES devices(id), idempotency_key TEXT NOT NULL, request_hash TEXT NOT NULL, recipient TEXT NOT NULL, amount BIGINT NOT NULL CHECK(amount > 0), currency TEXT NOT NULL, nonce TEXT NOT NULL UNIQUE, expires BIGINT NOT NULL, origin TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, UNIQUE(owner,idempotency_key))',
                'CREATE TABLE IF NOT EXISTS dispatches (intent TEXT PRIMARY KEY REFERENCES intents(id), record TEXT NOT NULL, state TEXT NOT NULL)',
                'CREATE TABLE IF NOT EXISTS audit (id BIGINT PRIMARY KEY, payload TEXT NOT NULL, previous TEXT NOT NULL, mac TEXT NOT NULL)',
            ]
            for sql in statements:
                db.execute(sql)
            db.execute('CREATE INDEX IF NOT EXISTS intents_owner_expires ON intents(owner,expires)')
            if self.postgres:
                for table in ('principals', 'devices', 'intents', 'dispatches', 'audit'):
                    db.execute(f'ALTER TABLE {table} ENABLE ROW LEVEL SECURITY')

    @contextmanager
    def transaction(self):
        db = self.connect()
        try:
            if self.postgres:
                db.execute('SELECT pg_advisory_xact_lock(781492731)')
            else:
                db.execute('BEGIN IMMEDIATE')
            yield db
            db.raw.commit()
        except BaseException:
            db.raw.rollback()
            raise
        finally:
            db.raw.close()

    def event(self, db, owner, intent, action):
        row = db.execute('SELECT id,mac FROM audit ORDER BY id DESC LIMIT 1').fetchone()
        seq, previous = (row['id'] + 1, row['mac']) if row else (1, '0' * 64)
        payload = canonical({'seq': seq, 'time': int(self.clock()), 'owner': owner, 'intent': intent, 'action': action})
        mac = hmac.new(self.audit_key, (previous + payload).encode(), hashlib.sha256).hexdigest()
        db.execute('INSERT INTO audit VALUES (?,?,?,?)', (seq, payload, previous, mac))

    def provision(self, owner, public_key):
        if not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', owner):
            raise Rejected('INVALID_OWNER')
        key = serialization.load_pem_public_key(public_key.encode())
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise Rejected('P256_REQUIRED')
        token, device = secrets.token_urlsafe(32), str(uuid.uuid4())
        with self.transaction() as db:
            exists = db.execute('SELECT id FROM principals WHERE id=?', (owner,)).fetchone()
            if exists:
                raise Rejected('OWNER_ALREADY_PROVISIONED')
            db.execute('INSERT INTO principals VALUES (?,?,?)', (owner, digest(token), int(self.clock()) + 3600))
            db.execute('INSERT INTO devices(id,owner,public_key) VALUES (?,?,?)', (device, owner, public_key))
            self.event(db, owner, device, 'DEVICE_PROVISIONED')
        return {'token': token, 'device': device, 'owner': owner}

    def authenticate(self, db, token):
        if not isinstance(token, str) or len(token) > 256:
            raise Rejected('UNAUTHENTICATED')
        row = db.execute('SELECT id FROM principals WHERE token_hash=? AND expires>?', (digest(token), int(self.clock()))).fetchone()
        if not row:
            raise Rejected('UNAUTHENTICATED')
        return row['id']

    def device(self, db, owner, identifier):
        row = db.execute('SELECT * FROM devices WHERE id=? AND owner=?', (identifier, owner)).fetchone()
        if not row or row['revoked']:
            raise Rejected('DEVICE_UNAVAILABLE')
        return row

    def challenge(self, token, request):
        if set(request) != {'device', 'recipient', 'amount_minor', 'currency', 'idempotency_key', 'source_url'}:
            raise Rejected('INVALID_FIELDS')
        if type(request['amount_minor']) is not int or not 1 <= request['amount_minor'] <= 100_000_000:
            raise Rejected('INVALID_AMOUNT')
        if request['currency'] not in ('BRL', 'USD', 'EUR'):
            raise Rejected('INVALID_CURRENCY')
        for field in ('recipient', 'idempotency_key'):
            if not isinstance(request[field], str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', request[field]):
                raise Rejected('INVALID_' + field.upper())
        if not isinstance(request['device'], str):
            raise Rejected('INVALID_DEVICE')
        if not screen_url(request['source_url'], {urlsplit(self.origin).hostname})['allowed']:
            raise Rejected('UNTRUSTED_SOURCE')
        request_hash = digest(canonical(request))
        with self.transaction() as db:
            owner = self.authenticate(db, token)
            self.device(db, owner, request['device'])
            old = db.execute('SELECT * FROM intents WHERE owner=? AND idempotency_key=?', (owner, request['idempotency_key'])).fetchone()
            if old:
                if old['request_hash'] != request_hash:
                    raise Rejected('IDEMPOTENCY_CONFLICT')
                return self.envelope(old)
            recent = db.execute('SELECT COUNT(*) AS n FROM intents WHERE owner=? AND expires>?', (owner, int(self.clock()) - 3600)).fetchone()['n']
            if recent >= 30:
                raise Rejected('RATE_LIMITED')
            identifier = str(uuid.uuid4())
            values = (identifier, owner, request['device'], request['idempotency_key'], request_hash, request['recipient'], request['amount_minor'], request['currency'], secrets.token_hex(32), int(self.clock()) + 120, self.origin, 'PENDING')
            db.execute('INSERT INTO intents(id,owner,device,idempotency_key,request_hash,recipient,amount,currency,nonce,expires,origin,state) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)', values)
            self.event(db, owner, identifier, 'CHALLENGE_CREATED')
            return self.envelope(db.execute('SELECT * FROM intents WHERE id=?', (identifier,)).fetchone())

    def envelope(self, row):
        payload = '\n'.join(('GUARD-V1', row['id'], row['owner'], row['device'], row['recipient'], str(row['amount']), row['currency'], row['nonce'], str(row['expires']), row['origin']))
        return {'id': row['id'], 'state': row['state'], 'payload': payload, 'payload_sha256': digest(payload), 'expires': row['expires']}

    def owned(self, db, token, identifier):
        owner = self.authenticate(db, token)
        row = db.execute('SELECT * FROM intents WHERE id=? AND owner=?', (identifier, owner)).fetchone()
        if not row:
            raise Rejected('NOT_FOUND')
        return owner, row

    def authorize(self, token, identifier, signature):
        error = None
        result = None
        with self.transaction() as db:
            owner, row = self.owned(db, token, identifier)
            device = self.device(db, owner, row['device'])
            if row['state'] != 'PENDING':
                error = 'INVALID_STATE'
            elif int(self.clock()) >= row['expires']:
                error = 'EXPIRED'
                db.execute("UPDATE intents SET state='EXPIRED' WHERE id=?", (identifier,))
            else:
                try:
                    if not isinstance(signature, str) or len(signature) > 256:
                        raise ValueError()
                    decoded = base64.b64decode(signature, validate=True)
                    serialization.load_pem_public_key(device['public_key'].encode()).verify(decoded, self.envelope(row)['payload'].encode(), ec.ECDSA(hashes.SHA256()))
                except (ValueError, InvalidSignature):
                    error = 'INVALID_SIGNATURE'
                    db.execute('UPDATE intents SET attempts=attempts+1,state=? WHERE id=?', ('LOCKED' if row['attempts'] >= 4 else 'PENDING', identifier))
                else:
                    db.execute("UPDATE intents SET state='AUTHORIZED' WHERE id=?", (identifier,))
                    result = {'id': identifier, 'state': 'AUTHORIZED'}
            self.event(db, owner, identifier, error or 'AUTHORIZED')
        if error:
            raise Rejected(error)
        return result

    def execute(self, token, identifier):
        error = None
        result = None
        with self.transaction() as db:
            owner, row = self.owned(db, token, identifier)
            self.device(db, owner, row['device'])
            if row['state'] != 'AUTHORIZED':
                error = 'INVALID_STATE'
            elif int(self.clock()) >= row['expires']:
                error = 'EXPIRED'
                db.execute("UPDATE intents SET state='EXPIRED' WHERE id=?", (identifier,))
            else:
                record = self.mainframe_record(row)
                db.execute("INSERT INTO dispatches VALUES (?,?,'QUEUED')", (identifier, record))
                db.execute("UPDATE intents SET state='QUEUED' WHERE id=?", (identifier,))
                result = {'id': identifier, 'state': 'QUEUED', 'record': record}
            self.event(db, owner, identifier, error or 'DISPATCH_QUEUED')
        if error:
            raise Rejected(error)
        return result

    def mainframe_record(self, row):
        return row['id'] + f"{row['amount']:012d}" + row['currency'] + row['recipient'].ljust(64) + 'A'

    def revoke(self, token, device):
        with self.transaction() as db:
            owner = self.authenticate(db, token)
            self.device(db, owner, device)
            db.execute('UPDATE devices SET revoked=1 WHERE id=?', (device,))
            self.event(db, owner, device, 'DEVICE_REVOKED')
        return {'state': 'REVOKED'}

    def verify_audit(self):
        with self.transaction() as db:
            previous = '0' * 64
            rows = db.execute('SELECT * FROM audit ORDER BY id').fetchall()
            for index, row in enumerate(rows, 1):
                expected = hmac.new(self.audit_key, (previous + row['payload']).encode(), hashlib.sha256).hexdigest()
                if row['id'] != index or row['previous'] != previous or not hmac.compare_digest(expected, row['mac']):
                    raise Rejected('AUDIT_CORRUPTED')
                previous = row['mac']
            return {'events': len(rows), 'head': previous}
