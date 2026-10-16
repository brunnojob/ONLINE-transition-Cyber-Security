# Interactive Python demo

The public lab executes `guard.core.Guard` on the server. It is not a JavaScript reimplementation or a replay of recorded output. `guard/demo.py` creates an isolated temporary SQLite database and ephemeral P-256 signing key for every request, invokes the original authorization and dispatch methods, verifies the audit chain and inspects final database state. Resources are discarded when the request finishes.

Six bounded scenarios are available: valid authorization, signed amount mismatch, signed recipient mismatch, authorization replay, expired challenge and eight competing dispatch calls. The expiration scenario advances an injected test clock, not wall time. The concurrency scenario uses four workers and eight real calls against the same temporary database. The browser accepts a fictional recipient and an integer-cent amount, displays server results and exports the returned report as JSON.

The signing key is generated on the server for demonstration. This does not establish trusted user confirmation, device-bound signing or protection of an actual bank account. The lab does not execute Java, Kotlin, Swift or COBOL; their recorded interoperability evidence remains separate. The local SQLite result is not evidence of PostgreSQL behavior under production load. The endpoint exposes no original gateway provisioning, database selection, arbitrary code execution or real payment adapter.

## Deployment

Vercel serves `web/` and runs `api/demo.py` as a Python Function. No database account or environment secret is needed. `scripts/build-demo.py` copies the recorded CI report into the static output. The existing Netlify configuration still publishes static files only and does not run the Python demo endpoint; deploy the interactive lab on Vercel.

Run the suite with `python -m unittest discover -s tests -v`. The HTTP tests exercise the deployed handler locally, including all six scenarios, input validation, content type and body limits. Public deployments use platform request controls; this is a bounded demo endpoint, not a production authorization service.
