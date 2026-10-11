# Supabase setup on Windows

This guide connects the Python backend to Supabase PostgreSQL. A connected Supabase MCP plugin does not configure the application's database connection. The application reads environment variables directly and does not automatically load a `.env` file.

## Download and install

Open [the repository](https://github.com/brunnojob/ONLINE-transition-Cyber-Security), select Code, then Download ZIP. Extract the archive and open the folder containing `requirements.txt`. Type `powershell` in that folder's address bar and press Enter.

Install Python 3.12 from [Python](https://www.python.org/downloads/windows/) if it is not available. Check the installation and create the environment:

```powershell
py -3.12 --version
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

The connection check and server do not require Java, Kotlin, Swift or COBOL. Those runtimes are used by their clients and interoperability proof.

## Obtain the connection string

Open the intended project in the Supabase dashboard. Select Connect, then Direct / Connection string. Scroll inside the dialog, select Session pooler under Connection Method and select URI under Type. Session pooling supports IPv4 connections and prepared statements.

Copy the entire connection string, including the part hidden by horizontal scrolling. Use the host, username and port supplied by the dashboard rather than constructing them manually.

In a local plain text editor, replace `[YOUR-PASSWORD]` with the database password, removing the brackets. Percent-encode reserved characters within the password. For example, an `@` inside the password becomes `%40`, while the `@` immediately before the server hostname remains unchanged. A literal `%` becomes `%25`. Do not encode the entire connection string or double-encode an already encoded password.

Append `?sslmode=require` if the URI has no query parameters, or `&sslmode=require` if it already contains a query. This requires encrypted transport; production certificate and hostname verification should use `sslmode=verify-full` with the appropriate CA configuration.

The resulting URI must be one line with no added spaces. Visual wrapping in the editor is acceptable; inserted newline characters are not. The following example contains placeholders, not usable credentials:

```text
postgresql://postgres.PROJECT_REF:ENCODED_PASSWORD@POOLER_HOST:5432/postgres?sslmode=require
```

Use the database password, not a Supabase API key. The SQL Editor executes SQL statements; do not paste a connection URI there. Resetting the database password requires updating every application using that password.

## Configure the current PowerShell session

Enter the URI privately when prompted:

```powershell
$env:GUARD_DATABASE = Read-Host 'Paste the complete PostgreSQL URI'
$env:GUARD_ORIGIN = 'https://guard.example'
```

The origin above is a local test configuration. Replace it with the application's real HTTPS origin when deploying. The URI prompt displays the pasted text on screen; do not share screenshots of it.

For the first setup of a new audit database, generate an audit key once:

```powershell
$env:GUARD_AUDIT_KEY = .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
```

Store that key in a private password manager before closing the terminal. To view it locally, run `$env:GUARD_AUDIT_KEY`. Never publish it. For subsequent sessions, restore the same key instead of generating another:

```powershell
$env:GUARD_AUDIT_KEY = Read-Host 'Paste the existing audit key'
```

Environment variables configured this way apply only to the current terminal and its child processes. Changing the audit key prevents verification of records created with the original key.

## Verify the live database

Run this command in the configured terminal:

```powershell
.\.venv\Scripts\python.exe -m guard.server audit
```

The command connects to the configured database, initializes the `txguard` schema and verifies the audit chain. It can create missing tables; it does not dispatch payments. An empty database returns `events` equal to zero and a `head` containing 64 zero characters. Existing valid audit data returns its event count and chain head.

In Supabase SQL Editor, verify the schema using this query:

```sql
SELECT tablename
FROM pg_tables
WHERE schemaname = 'txguard'
ORDER BY tablename;
```

Expect `audit`, `devices`, `dispatches`, `intents` and `principals`. The schema must remain outside the Data API's exposed schemas. This setup uses a trusted database owner connection; enabled RLS does not constrain the table owner. Backend ownership checks remain essential. Review `database/schema.sql` before initializing a shared project.

Do not set `TEST_DATABASE` to this shared or production database. The proof suite intentionally corrupts and clears test audit records and must use a disposable database.

## Start the local API

In the same configured terminal:

```powershell
.\.venv\Scripts\python.exe -m guard.server serve
```

Keep it open. In another PowerShell window:

```powershell
Invoke-RestMethod http://127.0.0.1:8080/health
```

Expect `status` equal to `ready` and `settlement` equal to `not-connected`. The latter describes the absent bank settlement adapter, not a failed PostgreSQL connection. Stop the server with Ctrl+C.

Netlify hosts this repository's static evidence viewer only. Configuring a Netlify environment variable does not deploy or start this Python server.

## Troubleshooting

| Result | Action |
| --- | --- |
| `py` is not recognized | Install Python with the Windows launcher and reopen PowerShell. |
| Python 3.12 is unavailable | Install that Python version before creating the virtual environment. |
| `requirements.txt` or the virtual environment is missing | Open PowerShell in the extracted repository folder and complete installation. |
| Authentication failed | Check the database password, password encoding and exact dashboard username. |
| Host lookup or network failure | Check the full hostname, Session pooler selection, project availability and network access. |
| Missing `GUARD_DATABASE`, `GUARD_ORIGIN` or `GUARD_AUDIT_KEY` | Set all three variables in the terminal that starts the command. |
| Audit verification fails after a restart | Restore the original audit key; investigate integrity failures without deleting records. |

Share only redacted error messages when asking for help. Keep database credentials, audit keys, private signing keys and bearer tokens out of GitHub and chat.

## Official documentation

- [Supabase PostgreSQL connections](https://supabase.com/docs/guides/database/connecting-to-postgres)
- [Supabase SSL connections](https://supabase.com/docs/guides/database/connecting-to-postgres#ssl-connections)
- [Supabase Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security)
