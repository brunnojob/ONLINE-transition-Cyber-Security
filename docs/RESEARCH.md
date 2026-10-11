# Research and design decisions

Reviewed on 2026-10-11.

The five supplied images are excerpts from “Protecting Online Transactions: A Cybersecurity Solution Model”, presented at the 2023 ICACITE conference. They identify phishing, spoofing, unencrypted data, malware, third-party risk and unauthorized transactions. The supplied excerpts do not provide a reproducible dataset, attack corpus or evaluation protocol supporting the listed 95–99% figures. This project does not reuse those figures or claim malware/ransomware detection.

| Primary source | Applied decision |
| --- | --- |
| [OWASP Transaction Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html) | Server-generated single-use challenge, immutable amount and recipient, explicit state transitions, expiration, failed-attempt lockout, execution-time authorization check |
| [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) | Do not label OTP or a software signing CLI as phishing-resistant authentication; require a separate authenticated verifier binding and protected key deployment before making that claim |
| [Supabase Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security) | Private schema, RLS enabled, no public policies or client table grants; application ownership checks remain mandatory |
| [PostgreSQL Explicit Locking](https://www.postgresql.org/docs/current/explicit-locking.html) | Transaction-scoped advisory lock serializes challenge/state/audit operations across workers; uniqueness constraints backstop duplicate dispatch prevention |
| [Java Signature API](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/Signature.html) | Standard SHA256withECDSA rather than custom cryptography |
| [Apple CryptoKit P256](https://developer.apple.com/documentation/cryptokit/p256/signing/privatekey) | Standard P256 signing and DER signature representation compatible with Python verification |
| [Supabase September 2026 PostgreSQL changes](https://supabase.com/changelog/postgres-15-19-17-11-breaking-changes) | Reviewed release notice; this schema uses no ltree, pgcrypto legacy PGP cipher, btree_gist float index or custom operator |

A forum search located [Bank scammer and banking app](https://security.stackexchange.com/questions/277646/bank-scammer-and-banking-app/277648). It was used to identify the social-engineering problem, not as the authority for cryptographic implementation. A genuine authorization prompt can still be abused by a scammer persuading the victim to approve it. Amount and recipient must therefore be displayed in a trusted confirmation interface. The CLI clients currently require operational control and do not implement that interface.

URL checks intentionally perform no HTTP request. Exact hostname matching, HTTPS enforcement, credential rejection and IP-literal rejection limit unsafe payment entry points without creating an SSRF-capable URL-fetch service. This is an allowlist control, not a statistical phishing classifier.
