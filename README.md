# FastAPI Security Lab

## Overview

This project is a deliberately vulnerable FastAPI application paired with a
hardened, security-fixed version of the same application. It exists to
demonstrate — end to end — the **vulnerability → exploitation → remediation**
workflow for common REST API security flaws:

1. A **vulnerable implementation** contains one specific, intentional flaw.
2. A **standalone exploit script** proves the flaw is real by attacking a
   locally running instance of the vulnerable app.
3. A **secure implementation** of the same endpoint fixes that exact flaw.
4. **Automated pytest tests** pin both behaviors down — one suite documents
   that the vulnerable app is still exploitable, the other regression-tests
   that the secure app resists the same attack.

Everything runs entirely on `127.0.0.1` against local SQLite databases. No
external systems, third-party hosts, or real user data are ever involved.
This is a learning/portfolio project, not production software.

## Security Objectives

- Show, with working code and a real exploit, exactly how each vulnerability
  class behaves — not just describe it.
- Show a concrete, correct fix for each flaw, implemented as an independent
  application rather than a toggle/flag.
- Back every fix with an automated regression test, so "secure" isn't just a
  claim — it's something `pytest` verifies on every run.
- Practice explaining API security findings the way a real assessment would:
  affected endpoint, root cause, impact, and remediation.

## Vulnerabilities Demonstrated

Three vulnerability categories are currently implemented, each with a
vulnerable endpoint, a secure fix, an exploit script, and automated tests.

### 1. BOLA / IDOR (Broken Object Level Authorization)

- **Affected endpoint:** `GET /users/{user_id}`
- **What's wrong:** The vulnerable endpoint checks that the caller is
  *authenticated* (has a valid JWT) but never checks that the caller is
  *authorized* to view the specific `user_id` being requested. Any logged-in
  user can fetch any other user's record by changing the ID in the URL.
- **Impact:** Full enumeration of user accounts (username, email, role) by
  any authenticated user, regardless of who they actually are.
- **OWASP mapping:** OWASP API Security Top 10 — **API1:2023 Broken Object
  Level Authorization**.
- **Exploit:** `exploits/exploit_bola.py` logs in as Alice, then reuses her
  own valid token to request `GET /users/2` (Bob's record) and shows the
  server returns Bob's data with HTTP 200.
- **Fix:** `secure_app`'s version adds an explicit authorization check —
  the caller must either own the requested record (`current_user.id ==
  user_id`) or hold the `admin` role. Everyone else gets `403 Forbidden`,
  returned *before* the database is even queried, so the check can't be used
  to enumerate which user IDs exist.

### 2. Mass Assignment

- **Affected endpoint:** `PUT /users/{user_id}`
- **What's wrong:** The vulnerable update endpoint correctly checks
  ownership (a user can only update their *own* profile), but then applies
  every field in the request body directly onto the database row with no
  allowlist (`for field, value in update_data.items(): setattr(user, field,
  value)`). Because the request schema includes `role` as an ordinary,
  client-writable field, a normal user can include `"role": "admin"` in an
  otherwise-innocent profile update and grant themselves administrator
  privileges.
- **Impact:** Full privilege escalation — a standard user becomes an admin
  in a single authenticated request, with no additional exploit needed.
- **OWASP mapping:** OWASP API Security Top 10 — **API6:2023 Unrestricted
  Access to Sensitive Business Flows** family / commonly referred to as
  **Mass Assignment** (also tracked historically as part of OWASP API3:2019
  Excessive Data Exposure's inverse case — over-*posting*, not over-*exposing*).
- **Exploit:** `exploits/exploit_mass_assignment.py` logs in as Alice
  (`role: "user"`), sends `PUT /users/1` with
  `{"email": "alice_new@example.com", "role": "admin"}`, and shows her role
  changes to `"admin"` in the response and on a follow-up `GET`.
- **Fix:** `secure_app`'s update schema (`UserUpdate`) is a strict allowlist
  containing only `username` and `email`, with `model_config =
  ConfigDict(extra="forbid")` — any unexpected field (including `role`)
  causes Pydantic to reject the whole request with `422 Unprocessable
  Entity` before the endpoint code even runs. As defense in depth, the
  endpoint itself also assigns only the two known-safe fields by name,
  rather than looping over arbitrary request keys.

### 3. Weak JWT Secret

- **Affected component:** JWT signing in `vulnerable_app/auth.py`,
  exercised through `GET /admin`
- **What's wrong:** The vulnerable app signs and verifies all JWTs with a
  hardcoded secret, `JWT_SECRET_KEY = "supersecret"`, defined directly in
  source. Since this project's source is public, that secret is public too.
- **Important finding (how the exploit actually works):** `GET /admin`
  checks `current_user.role`, and `get_current_user()` re-derives that role
  by looking the user up in the database using the JWT's `sub` (user ID)
  claim — it does **not** trust a `role` value embedded in the token
  directly. This means forging a token with `sub="1"` (Alice's real ID) and
  `role="admin"` does **not** grant admin access, because the server still
  looks up Alice's real database role (`"user"`). The actual exploit is more
  serious: since `sub` is just as forgeable as any other claim, an attacker
  who knows the signing secret can mint a token with `sub="3"` — the real
  admin account's database ID — and fully impersonate the admin account,
  with no password required at all.
- **Impact:** Complete authentication bypass / account impersonation for
  any user ID, including the real administrator account, by anyone who has
  read the (public) source code.
- **OWASP mapping:** OWASP API Security Top 10 — **API2:2023 Broken
  Authentication** (weak/guessable/hardcoded signing secrets undermining
  token integrity).
- **Exploit:** `exploits/exploit_weak_jwt.py` logs in as Alice for a
  baseline comparison, confirms her real token correctly gets `403` from
  `/admin`, then forges two tokens signed with `"supersecret"`: one with
  `sub="1", role="admin"` (shown to still fail, with an explanation of why),
  and one with `sub="3"` (the real admin's ID), which succeeds with `200`.
- **Fix:** `secure_app/auth.py` never hardcodes a secret. It reads
  `JWT_SECRET_KEY` exclusively from the `SECURE_APP_JWT_SECRET` environment
  variable and **refuses to start** (raises `RuntimeError` at import time)
  if that variable is missing or shorter than 32 characters — no silent
  fallback to any default, weak or otherwise. A token forged with
  `"supersecret"` fails signature verification against `secure_app` and is
  rejected with `401` before any role or ID logic even runs.

### Related robustness fix (both apps)

While reviewing the JWT handling above, a related bug was found and fixed in
**both** apps' `get_current_user()`: a token with a non-numeric `sub` claim
used to raise an unhandled `ValueError` when converted with `int()`,
producing a raw `500 Internal Server Error`. Both apps now catch this
alongside JWT decoding errors and return a clean `401 Unauthorized` instead.
This is a correctness fix, not a new vulnerability category — it doesn't
change the intentional vulnerable behavior above.

## Vulnerable vs. Secure Architecture

`vulnerable_app/` and `secure_app/` are **completely separate FastAPI
applications** — separate Python packages, separate routers, separate
`auth.py`, and separate SQLite database files (`vulnerable.db` and
`secure.db`). Nothing is shared or toggled by a flag. This is deliberate:
it keeps the vulnerable code simple and honest (nothing about the fix leaks
into it) and makes every comparison a true side-by-side — same request
shape, two independently-implemented outcomes.

## API Endpoints

Both applications expose the same route surface; behavior differs as
described above.

### `vulnerable_app` (http://127.0.0.1:8000)

| Method | Path | Auth required | Behavior |
|---|---|---|---|
| GET | `/health` | No | Liveness check — `{"status": "ok"}` |
| POST | `/login` | No | Verifies credentials, issues an HS256 JWT signed with the hardcoded `"supersecret"` |
| GET | `/users/{user_id}` | Yes (JWT) | **Vulnerable — BOLA/IDOR:** returns any user's data, no ownership check |
| PUT | `/users/{user_id}` | Yes (JWT), ownership checked | **Vulnerable — Mass Assignment:** applies any field in the body, including `role`, with no allowlist |
| GET | `/admin` | Yes (JWT) | Checks the caller's `role` (read from the database via the token's `sub`) |

### `secure_app` (http://127.0.0.1:8001)

| Method | Path | Auth required | Behavior |
|---|---|---|---|
| GET | `/health` | No | Liveness check — `{"status": "ok"}` |
| POST | `/login` | No | Verifies credentials, issues an HS256 JWT signed with the secret from `SECURE_APP_JWT_SECRET` |
| GET | `/users/{user_id}` | Yes (JWT) | **Fixed:** self-or-admin only; `403` otherwise |
| PUT | `/users/{user_id}` | Yes (JWT), ownership checked | **Fixed:** strict `username`/`email` allowlist; unexpected fields (e.g. `role`) → `422` |
| GET | `/admin` | Yes (JWT) | Requires `role == "admin"`; unreachable via a token forged with the vulnerable app's secret |

## Project Structure

```
fastapi-security-lab/
├── vulnerable_app/          # Intentionally insecure FastAPI app
│   ├── auth.py               # Password/JWT handling (hardcoded weak secret)
│   ├── database.py           # SQLAlchemy engine/session (vulnerable.db)
│   ├── main.py                # App entrypoint, registers routers
│   ├── models.py              # User, Order SQLAlchemy models
│   ├── schemas.py             # Pydantic request/response schemas
│   ├── seed_data.py           # Deterministic demo data
│   └── routers/
│       ├── login.py, users.py, admin.py
├── secure_app/               # Hardened counterpart — same shape, fixed logic
│   └── (same layout as vulnerable_app/)
├── exploits/                 # Standalone attack scripts (target vulnerable_app only)
│   ├── exploit_bola.py
│   ├── exploit_mass_assignment.py
│   └── exploit_weak_jwt.py
├── tests/                    # Automated pytest suite
│   ├── conftest.py
│   ├── test_vulnerable_security.py
│   └── test_secure_security.py
├── docs/
│   ├── screenshots/           # (reserved for future PoC screenshots)
│   └── vulnerabilities/       # (reserved for future per-vulnerability write-ups)
├── evidence/                  # (reserved for future raw request/response captures)
├── requirements.txt
├── .gitignore
└── README.md
```

## Setup

Requires Python 3.11+ (developed and tested on Python 3.12).

```bash
cd fastapi-security-lab

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Seed the databases

Each app has its own seed script and its own SQLite file. Run each once
before starting the corresponding server:

```bash
python -m vulnerable_app.seed_data
python -m secure_app.seed_data
```

Both scripts drop and recreate their tables, then insert three deterministic
demo users (local lab credentials only — not real accounts):

| Username | Password | Role |
|---|---|---|
| `alice` | `alice_password123` | `user` |
| `bob` | `bob_password123` | `user` |
| `admin` | `admin_password123` | `admin` |

### Run `vulnerable_app` (port 8000)

```bash
uvicorn vulnerable_app.main:app --host 127.0.0.1 --port 8000
```

No extra configuration needed — the JWT secret is intentionally hardcoded
for this app.

### Run `secure_app` (port 8001)

`secure_app` **requires** `SECURE_APP_JWT_SECRET` to be set — it refuses to
start otherwise. Generate a strong secret and export it first:

```bash
export SECURE_APP_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
uvicorn secure_app.main:app --host 127.0.0.1 --port 8001
```

This secret is generated fresh for local use and is never written to a
file. It must **not** be committed to GitHub — if you keep it in a `.env`
file for convenience, note that `.env` is already listed in `.gitignore`.

## Exploitation

The exploit scripts are **local lab tools only** — every request target is
hardcoded to `http://127.0.0.1:8000` (the running `vulnerable_app`). They
are not written to, and must not be pointed at, any other host.

With `vulnerable_app` running and seeded (see Setup above), in a separate
terminal:

```bash
source .venv/bin/activate

python exploits/exploit_bola.py
python exploits/exploit_mass_assignment.py
python exploits/exploit_weak_jwt.py
```

Each script logs in with real, legitimate demo credentials, prints the
request/response for each step, and ends with a clear `RESULT:` line
explaining what it proved. None of them print a complete JWT — only short
prefixes are shown, consistent with how you'd handle a token in a real
assessment.

## Security Fixes

| Vulnerability | Fix summary |
|---|---|
| BOLA / IDOR | `secure_app` adds an explicit object-level authorization check (self-or-admin) on `GET /users/{user_id}`, returning `403` before querying the target record. |
| Mass Assignment | `secure_app` replaces the open update schema with a strict allowlist (`username`, `email` only) using `extra="forbid"`, plus explicit field-by-field assignment in the endpoint — `role` can never reach the database through this endpoint. |
| Weak JWT Secret | `secure_app` loads the signing secret only from `SECURE_APP_JWT_SECRET`, requires a minimum length, and fails to start rather than falling back to any default. |
| Non-numeric `sub` claim (robustness) | Both apps now catch `ValueError` alongside JWT decode errors in `get_current_user()`, returning `401` instead of an unhandled `500`. |

## Automated Security Tests

The suite lives in `tests/` and is split by intent:

- **`tests/test_vulnerable_security.py`** — tests here **intentionally
  assert the vulnerable behavior**. For example, the BOLA test asserts that
  Alice's token retrieves Bob's record with `200` — that's the documented
  flaw, not a bug in the test. If `vulnerable_app` were ever accidentally
  hardened, these tests would fail, flagging that the demo no longer
  matches what's documented.
- **`tests/test_secure_security.py`** — these are genuine **regression
  tests**: they assert the fixed, secure behavior (e.g. `403` on
  cross-user access, `422` on an unexpected `role` field). A failure here
  represents an actual security regression.
- **`tests/conftest.py`** — supplies a fresh, strong `SECURE_APP_JWT_SECRET`
  for the test session only, so `secure_app` can be imported and tested
  (satisfying its own fail-safe startup check honestly).

All tests run in-process via FastAPI's `TestClient` — no real network
calls, no running server required.

```bash
python -m pytest tests/ -v
```

**Current result: 18 passed.**

## Learning Outcomes

This project was built to practice and demonstrate:

- The difference between **authentication** (who are you) and
  **authorization** (what are you allowed to do) — and how an API can get
  the first right while completely missing the second.
- **BOLA/IDOR**: why object-level authorization has to be checked on every
  request, not just once at login.
- **Mass assignment**: why request schemas need an explicit allowlist
  rather than trusting whatever fields a client happens to send.
- **JWT security fundamentals**: what a signature actually proves (and
  doesn't prove), and why a hardcoded or weak signing secret undermines the
  entire authentication scheme.
- **Secure secret management**: loading secrets from the environment,
  enforcing a minimum strength, and failing safely (refusing to start)
  rather than silently degrading.
- **Negative security testing**: writing tests that prove an attack *fails*
  against the secure implementation, not just that normal use *succeeds*.
- **Exploit development in a controlled local lab**: writing small, clearly
  scoped scripts that prove a vulnerability with real HTTP requests against
  `127.0.0.1` only.
- **Security regression testing**: encoding "this must never happen again"
  as an automated, repeatable test rather than a one-time manual check.

## Limitations / Current Scope

**Only the three vulnerability categories listed above are currently
implemented and tested.** To be explicit about what is *not* in this
project yet:

- **No rate limiting** is implemented anywhere — `/login` and every other
  endpoint currently accept unlimited requests.
- **No dedicated input-validation vulnerability demonstration** exists
  beyond what Pydantic enforces by default.
- **No additional Broken Authentication scenarios** (e.g. account lockout,
  password strength rules, credential stuffing defenses) are implemented.
- **There is no `/orders` API.** An `Order` SQLAlchemy model exists in
  `models.py` and is populated by `seed_data.py` for possible future use,
  but no router or endpoint currently exposes it.
- **There is no `/profile` API.** Self-profile viewing and updating is
  handled through `GET`/`PUT /users/{user_id}`, not a separate route.

This project does **not** claim to cover the full OWASP API Security Top
10 — three related, high-impact categories were chosen and implemented in
depth rather than covering all categories shallowly.

## Future Extensions

Possible directions if this project continues (none of these exist yet):

- Missing rate limiting as its own demonstrated vulnerability (e.g. brute
  force against `/login`).
- A dedicated improper input validation scenario.
- OAuth2/OIDC-based authentication as a comparison to the current JWT flow.
- Broader OWASP API Security Top 10 coverage (e.g. excessive data exposure,
  security misconfiguration).
- Manual testing walkthroughs using Burp Suite against the vulnerable app.
- CI-based automated security checks (e.g. running the pytest suite and a
  dependency vulnerability scan on every push).

## Disclaimer

This project is **intentionally vulnerable** and built strictly for local,
authorized security education and self-testing. It is not production code,
has not undergone professional security review, and should never be
deployed anywhere other than a local, isolated environment. Do not reuse
`vulnerable_app`'s code, secrets, or patterns in any real system.
