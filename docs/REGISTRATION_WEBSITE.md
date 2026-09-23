# Registration website + SQLite accounts

This feature adds a local web registration service backed by SQLite.

## What it does

- Creates accounts with unique, case-insensitive usernames.
- Allocates Assault Fire UINs starting at **10001**.
- Stores only PBKDF2-HMAC-SHA256 password hashes and random salts.
- Creates an empty profile row for each account so nickname/profile data can be
  attached later.
- Uses SQLite WAL mode so the registration site and emulator can safely open the
  same database.
- Provides CSRF protection and basic browser security headers.
- Does not replace the stable v94 player-state JSON yet.

The database defaults to:

\`\`\`text
server/assaultfire_accounts.sqlite3
\`\`\`

Override it with:

\`\`\`text
AF_ACCOUNT_DB=C:\path\to\assaultfire_accounts.sqlite3
\`\`\`

## Install

From the repository root:

\`\`\`powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
\`\`\`

## Run the website

Local-only default:

\`\`\`powershell
.\.venv\Scripts\python.exe .\web\app.py
\`\`\`

Then open:

\`\`\`text
http://127.0.0.1:8080/register
\`\`\`

Optional settings:

\`\`\`powershell
$env:AF_WEB_HOST = "127.0.0.1"
$env:AF_WEB_PORT = "8080"
$env:AF_WEB_SECRET = "replace-with-a-long-random-secret"
$env:AF_ACCOUNT_DB = "C:\path\to\assaultfire_accounts.sqlite3"
.\.venv\Scripts\python.exe .\web\app.py
\`\`\`

For local testing, the app generates a temporary web secret when
\`AF_WEB_SECRET\` is not set. Set a persistent secret before deploying the site
beyond a local test machine.

## Current v94 integration boundary

The public stable v94 AUTH handler currently returns a hard-coded successful
account result with UIN **10001** and ticket \`LOCAL_TICKET_001\`. It does not
yet decode and validate the launcher AP cmd-3 username/password fields.

For that reason, this feature intentionally does **not** make the SQLite
database authoritative for launcher login yet. Doing so before the PH cmd-3
credential layout is verified would risk breaking the known-good TCLS login
path.

The intended next integration is:

1. Decode the observed AP cmd-3 credential fields.
2. Call \`server.account_db.verify_account(...)\`.
3. Return the registered account's UIN in AP cmd-4.
4. Generate/store a per-login ticket tied to that UIN.
5. Carry that UIN through ROLE/ZONE instead of the current single-player
   constants.
6. Migrate per-player profile/inventory persistence from one JSON file to
   SQLite after multi-account login is working.

## Tests

The account layer uses the standard library test runner:

\`\`\`powershell
.\.venv\Scripts\python.exe -m unittest tests.test_account_db -v
\`\`\`
