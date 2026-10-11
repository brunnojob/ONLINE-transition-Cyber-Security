# Threat model and operational boundary

Assets: authorized transaction content, device public-key bindings, opaque session tokens, signing private keys, dispatch uniqueness and audit integrity.

The attacker may control transaction request fields, hold another user's session token, replay signatures, submit malformed authorization data, race executions or replace a payment URL. The attacker is assumed not to possess the legitimate device private key, operator database credentials or the audit HMAC key.

The backend checks ownership from a hashed opaque token, never from a caller-supplied owner. Tokens expire after one hour. Enrollment is an operator-only CLI operation, not a public API. One owner has one initially provisioned device; public enrollment, identity verification and recovery are deliberately absent. Device revocation blocks both approval and dispatch.

Signatures cover an ASCII, newline-delimited envelope containing version, intent UUID, owner, device, recipient, integer minor-unit amount, currency, nonce, expiry and configured origin. Restrictive identifier validation prevents delimiter injection. ECDSA uses NIST P-256 with SHA-256 and DER encoding. Private keys are never transmitted to the backend.

The PostgreSQL implementation uses a private txguard schema and enables RLS with no public access policies. The backend connects as the schema/table owner and therefore bypasses RLS by design; application ownership checks enforce authorization. Do not expose this schema through the Supabase Data API. Do not grant anon/authenticated table access. Administrative database access can bypass application controls.

The global PostgreSQL transaction advisory lock and SQLite BEGIN IMMEDIATE prioritize correctness over throughput. They serialize writes and audit appends. This is not a high-throughput benchmark. A later partitioned design needs per-account locking and a separate audit sequencer. The unique dispatch primary key gives at-most-once local queue insertion; it does not give exactly-once external bank settlement.

The HMAC audit chain detects alteration and removal inside the chain. It does not detect rollback to an earlier complete database snapshot or tail truncation without an externally retained head checkpoint. It is not immutable storage. Export the audit head to an independently protected store; separate the HMAC key from the database and rotate it only through an explicit archival plan.

The Java, Kotlin and Swift CLI signers load exportable PKCS8 private keys. They are interoperability tools, not authenticated mobile banking applications. Expected origin must come from trusted configuration. There is no Secure Enclave/Android Keystore deployment, WebAuthn ceremony, authenticated signing UI, malware detector, ransomware protection, fraud accuracy claim or NIST certification. A compromised client or a victim intentionally approving a fraudulent beneficiary can defeat this boundary.

The Python HTTP adapter binds to loopback, caps JSON bodies, rejects duplicate JSON keys, forbids unexpected fields and sets a read timeout. It is a local reference adapter. Public hosting requires a maintained production HTTP stack, TLS reverse proxy, request/concurrency limits, trusted-origin configuration, secret management, monitoring and protected administrative enrollment. The challenge rate limit is per principal; unauthenticated network-level abuse is the gateway's responsibility.

The mainframe record is 116 ASCII bytes. The COBOL gate validates format, amount, currency and the authorization marker; that marker is not a cryptographic proof. Only a mutually authenticated backend-to-mainframe channel may deliver these records. JCL contains installation placeholders and has not run on IBM z/OS. A bank adapter must preserve the intent UUID as its idempotency key, authenticate acknowledgments and reconcile ambiguous outcomes. This repository neither moves funds nor reports a queued transfer as settled.

Report vulnerabilities privately to the repository owner before public disclosure. Do not include signing keys, session tokens, real account numbers or production customer data in issues or test artifacts.
