# FastAPI Security Lab
## Vulnerability Reports

Detailed write-ups document each vulnerability, its root cause, reproduction steps, security impact, remediation, and verification.

1. [BOLA / IDOR — Broken Object Level Authorization](docs/vulnerabilities/01-bola-idor.md)
2. [Mass Assignment — Unauthorized Role Modification](docs/vulnerabilities/02-mass-assignment.md)
3. [Weak JWT Secret — Token Forgery and Account Impersonation](docs/vulnerabilities/03-weak-jwt.md)
4. [Improper Input Validation — Orders API](docs/vulnerabilities/04-improper-input-validation.md)
5. [Broken Function Level Authorization — Admin Users Endpoint](docs/vulnerabilities/05-broken-function-level-authorization.md)
6. [Unrestricted Resource Consumption — Admin Users Listing](docs/vulnerabilities/06-unrestricted-resource-consumption.md)
7. [Brute-Force Authentication — Unthrottled Login](docs/vulnerabilities/07-brute-force.md)
8. [Account Lockout and Authentication Hardening](docs/vulnerabilities/08-account-lockout.md)
9. [Security Misconfiguration — CORS and Missing Security Headers](docs/vulnerabilities/09-security-misconfiguration.md)
10. [JWT Algorithm-Verification Flaw (alg:none)](docs/vulnerabilities/10-jwt-algorithm-verification.md)

Supporting security test evidence is available in the [`evidence/`](evidence/) directory.
## Overview

This project is a deliberately vulnerable FastAPI application paired with a hardened, security-fixed version of the same application. It demonstrates the **vulnerability → exploitation → remediation** workflow for common REST API security flaws:

1. A **vulnerable implementation** contains one specific, intentional flaw.
2. A **standalone exploit script** proves the flaw is real by attacking a locally running instance of the vulnerable app.
3. A **secure implementation** of the same endpoint fixes that exact flaw.
4. **Automated pytest tests** pin both behaviors down — one suite documents that the vulnerable app is still exploitable, the other regression-tests that the secure app resists the same attack.

Everything runs entirely on `127.0.0.1` against local SQLite databases. No external systems, third-party hosts, or real user data are ever involved. This is a learning/portfolio project, not production software.

## Security Objectives

- Show, with working code and a real exploit, exactly how each vulnerability class behaves — not just describe it.
- Show a concrete, correct fix for each flaw, implemented as an independent application rather than a toggle/flag.
- Back every fix with automated regression tests, so security claims are verified by `pytest`.
- Practice explaining API security findings the way a real assessment would: affected endpoint, root cause, impact, and remediation.
- Demonstrate login rate limiting as a security control and verify its behavior with an automated regression test.

## Vulnerabilities Demonstrated

Ten security topics are demonstrated across the two applications, each with a vulnerable behavior or missing control, a secure fix, an exploit or demonstration script, and automated tests.

### 1. BOLA / IDOR (Broken Object Level Authorization)

- **Affected endpoint:** `GET /users/{user_id}`
- **What's wrong:** The vulnerable endpoint checks that the caller is authenticated (has a valid JWT) but never checks that the caller is authorized to view the specific `user_id` being requested. Any logged-in user can fetch another user's record by changing the ID in the URL.
- **Impact:** Any authenticated user can enumerate user records, including usernames, email addresses, and roles.
- **OWASP mapping:** OWASP API Security Top 10 — **API1:2023 Broken Object Level Authorization**.
- **Exploit:** `exploits/exploit_bola.py` logs in as Alice, then reuses her valid token to request `GET /users/2` (Bob's record). The vulnerable server returns Bob's data with HTTP `200 OK`.
- **Fix:** `secure_app` adds an explicit authorization check. The caller must either own the requested record (`current_user.id == user_id`) or hold the `admin` role. Other callers receive `403 Forbidden`.

### 2. Mass Assignment

- **Affected endpoint:** `PUT /users/{user_id}`
- **What's wrong:** The vulnerable update endpoint checks ownership, but applies every field in the request body directly to the database row without an allowlist. Because the update schema permits the `role` field, a normal user can submit `"role": "admin"` in a profile update and grant themselves administrator privileges.
- **Impact:** A standard user can escalate privileges with a single authenticated request.
- **OWASP mapping:** OWASP API Security Top 10 — **API3:2023 Broken Object Property Level Authorization**. The vulnerable endpoint accepts a client-supplied value for the privileged, system-controlled `role` property during a profile update. The object-level ownership check is correct; the control that is missing is property-level authorization.
- **Exploit:** `exploits/exploit_mass_assignment.py` logs in as Alice (`role: "user"`), sends `PUT /users/1` with `{"email": "alice_new@example.com", "role": "admin"}`, and demonstrates that her role changes to `"admin"`.
- **Fix:** `secure_app` uses a strict `UserUpdate` schema that permits only `username` and `email`, with `ConfigDict(extra="forbid")`. Unexpected fields such as `role` are rejected with `422 Unprocessable Entity`. The endpoint also assigns only the two explicitly allowed fields.

### 3. Weak JWT Secret

- **Affected component:** JWT signing in `vulnerable_app/auth.py`, exercised through `GET /admin`.
- **What's wrong:** The vulnerable app signs and verifies JWTs with the hardcoded secret `JWT_SECRET_KEY = "supersecret"`. Since the project's source is public, the secret is public too.
- **Important finding:** `GET /admin` checks `current_user.role`. The application derives that role from the database using the JWT's `sub` claim; it does not trust a `role` claim embedded in the token. Forging a token with `sub="1"` and `role="admin"` therefore does not make Alice an administrator. However, an attacker who knows the signing secret can forge a token with `sub="3"` — the real admin account's database ID — and impersonate that account.
- **Impact:** Authentication bypass and account impersonation for users whose IDs an attacker can identify, including the administrator.
- **OWASP mapping:** OWASP API Security Top 10 — **API2:2023 Broken Authentication**.
- **Exploit:** `exploits/exploit_weak_jwt.py` logs in as Alice for a baseline, confirms her real token receives `403` from `/admin`, and forges two tokens using `"supersecret"`. The token with `sub="1"` still fails, while the token with `sub="3"` succeeds.
- **Fix:** `secure_app/auth.py` reads the JWT signing secret exclusively from the `SECURE_APP_JWT_SECRET` environment variable. It refuses to start if the variable is missing or the secret is shorter than 32 characters. A token signed using `"supersecret"` fails signature verification against the secure application and is rejected with `401 Unauthorized`.

### 4. Improper Input Validation (Orders API)

- **Affected endpoint:** `POST /orders`
- **What's wrong:** The vulnerable create-order schema accepts `quantity` and `unit_price` with no value constraints, so a negative quantity is accepted and the server computes and persists a negative line total (for example, `amount = -500.0`). The owner is derived from the authenticated user and the total is computed server-side, so this is strictly an input-validation / data-integrity defect, not owner spoofing or a client-dictated total.
- **Impact:** A standard authenticated user can create impossible orders (negative totals) that corrupt stored business data.
- **CWE mapping:** **CWE-20 (Improper Input Validation)** and **CWE-1284 (Improper Validation of Specified Quantity in Input)**. This is an input-validation defect, not an OWASP object-/property-level authorization issue, so it is deliberately not mapped to API1/API3.
- **Exploit:** `exploits/exploit_improper_input_validation.py` logs in as Alice, sends a valid control order, then an invalid order with `quantity=-5`, and reports the status codes (`201` with a negative total against the vulnerable app, `422` against the secure app).
- **Fix:** `secure_app` uses a strict `OrderCreate` schema: `quantity` and `unit_price` must be greater than zero, finite (NaN/Infinity rejected via `allow_inf_nan=False`), and bounded (`<= 1,000,000`, which keeps the computed total finite); `product` must be non-empty; and `extra="forbid"` blocks unexpected fields. Invalid input is rejected with `422` before any order is created; the total is computed server-side and the owner is taken from the authenticated user.

### 5. Broken Function Level Authorization (BFLA)

- **Affected endpoint:** `GET /admin/users`
- **What's wrong:** The vulnerable app adds an administrative "list all users" endpoint that checks only that the caller is authenticated, not that they hold the `admin` role. Any ordinary logged-in user can call it and enumerate every account (usernames, emails, roles). The existing `GET /admin` is unchanged; this is a separate, new administrative function that simply omits the role check.
- **Impact:** A low-privilege user can invoke an admin-only function and read all users' data; on a state-changing admin function the same flaw would allow privilege escalation.
- **OWASP mapping:** OWASP API Security Top 10 — **API5:2023 Broken Function Level Authorization** (CWE-285 Improper Authorization / CWE-862 Missing Authorization).
- **Exploit:** `exploits/exploit_bfla.py` logs in as Alice (role `user`) and calls `GET /admin/users`: the vulnerable app returns `200` with the full user list, the secure app returns `403`.
- **Fix:** `secure_app` enforces `current_user.role == "admin"` on the endpoint, returning `403` for non-admins before any data is read. The response schema (`UserOut`) never includes `password_hash` in either app.

### 6. Unrestricted Resource Consumption (Admin Users Listing)

- **Affected endpoint:** `GET /admin/users`
- **What's wrong:** The vulnerable app returns the entire `users` table in one response with no pagination and no page-size cap (`db.query(User).all()`), and ignores any client-supplied `limit`. A single request's cost scales with the whole dataset, enabling resource exhaustion / bulk retrieval as the table grows.
- **Impact:** A single cheap request can force an arbitrarily large response (CPU/memory/bandwidth), a denial-of-service and mass-retrieval primitive at scale.
- **OWASP mapping:** OWASP API Security Top 10 — **API4:2023 Unrestricted Resource Consumption** (CWE-770 Allocation of Resources Without Limits or Throttling / CWE-400).
- **Exploit:** `exploits/exploit_unrestricted_resource_consumption.py` logs in as admin and sends `GET /admin/users?limit=100000` and `?limit=1`: the vulnerable app accepts the oversized request (`200`) and ignores `limit`; the secure app rejects the oversized request (`422`) and honors `limit=1`.
- **Fix:** `secure_app` adds validated pagination — `limit` (1–100, default 20) and `offset` (>= 0) — with a deterministic `ORDER BY id`, so a client cannot request an unbounded or oversized page (invalid values return `422`). The admin-role check and the safe `UserOut` schema are preserved.

### 7. Brute-Force Authentication (Unthrottled Login)

- **Affected endpoint:** `POST /login`
- **What's wrong:** The vulnerable login applies no throttling — no rate limit and no account lockout — so an attacker can submit unlimited password guesses for a known username, each answered `401`. This is the precondition for online brute force and credential stuffing.
- **Impact:** Weak or reused passwords become practically discoverable at the server's full request rate; the most direct path to account takeover.
- **OWASP mapping:** OWASP API Security Top 10 — **API2:2023 Broken Authentication** (CWE-307 Improper Restriction of Excessive Authentication Attempts / CWE-799).
- **Exploit:** `exploits/exploit_brute_force.py` sends a small fixed burst (8) of wrong-password attempts: the vulnerable app answers every one `401` (unthrottled), while the secure app answers the first 5 `401` and the rest `429`.
- **Fix:** `secure_app` keeps its existing SlowAPI rate limit of 5 requests/minute per client IP on `POST /login` (see `secure_app/limiter.py`); the 6th attempt in the window is rejected with `429` before credentials are checked. IP-based rate limiting is distinct from account lockout and from MFA; see the report for the trade-offs and the client-IP-trust caveat.

### 8. Account Lockout and Authentication Hardening

- **Affected endpoint:** `POST /login` (control added to `secure_app`; `vulnerable_app` unchanged)
- **What it adds:** A per-account temporary lockout on top of the existing per-IP rate limit. After **5 consecutive failed-password attempts** on an existing account, the secure app locks that account for **15 minutes**; while locked, even the correct password is refused. The vulnerable app has no lockout, so its correct password still works after any number of failures.
- **Why it matters:** IP rate limiting and account lockout defend against different attacker models — a single fast IP vs. distributed guessing against one account. Layering both is stronger than either alone (defense-in-depth for OWASP **API2:2023 Broken Authentication** / **CWE-307**).
- **Anti-enumeration:** a locked account returns the same generic `401 Invalid username or password` as a wrong password or unknown username (no distinct `423`), so lock state does not disclose which accounts exist.
- **Trade-offs (documented in the report):** a hard per-account lock enables a targeted lockout DoS (an attacker can lock a victim out with 5 wrong guesses); alternatives include progressive backoff, IP/device-scoped tracking, CAPTCHA, self-service unlock, and MFA. The counter update is not atomic under true concurrency on SQLite, and a persistent DB would need a real migration — both are stated honestly, not claimed as production-grade.
- **Demo:** `exploits/exploit_account_lockout.py` (loopback-only, 6 requests) makes 5 failed attempts, waits one per-IP rate-limit window, then tries the correct password: the vulnerable app returns `200` (no lockout), the secure app returns `401` (locked).

### 9. Security Misconfiguration (CORS and Missing Security Headers)

- **Affected component:** application-level middleware (CORS + response headers), observed on every endpoint (demonstrated on `GET /health`).
- **What's wrong:** The vulnerable app uses a wide-open CORS policy (`allow_origins=["*"]` **with** `allow_credentials=True`), which makes Starlette **reflect any caller's `Origin`** and return `Access-Control-Allow-Credentials: true`, and it sets no security headers. A logged-in victim's browser on any site could read the API's authenticated responses, and the app can be framed (clickjacking) or MIME-sniffed.
- **OWASP mapping:** OWASP API Security Top 10 — **API8:2023 Security Misconfiguration** (CWE-942 Permissive Cross-domain Policy, CWE-1021 clickjacking, CWE-16/CWE-693).
- **Exploit:** `exploits/exploit_security_misconfiguration.py` (loopback-only, GET/OPTIONS on `/health`) sends an `Origin: https://evil.example` header and inspects the response: the vulnerable app reflects that origin with credentials and sends no security headers; the secure app does not echo the origin, rejects the disallowed preflight with `400`, and sends the headers.
- **Fix:** `secure_app` restricts CORS to an explicit, configurable allowlist (`SECURE_APP_ALLOWED_ORIGINS`, never a wildcard) and adds `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'`, and `Referrer-Policy: no-referrer` to every response. (HSTS is set but only takes effect over HTTPS and provides no protection for this plain-HTTP lab — documented, not claimed.)
- **Note:** these tests and the demo verify the **server's response headers** via `TestClient`, not full browser same-origin enforcement.

### 10. JWT Algorithm-Verification Flaw (alg:none)

- **Affected component:** JWT verification (`vulnerable_app/auth.py: get_current_user`), demonstrated on `GET /admin`.
- **What's wrong:** The vulnerable verifier trusts the algorithm the token declares in its own header, so a token with `alg:"none"` is accepted **without any signature check**. An attacker can forge a token for any user id (e.g. the admin's `sub="3"`) and impersonate them **without knowing the signing secret**. This is an *intentionally introduced* educational flaw — both apps previously pinned HS256.
- **Impact:** Complete authentication bypass / admin impersonation with no secret, password, or session — more severe than the weak-secret finding, which still requires the key.
- **OWASP mapping:** OWASP API Security Top 10 — **API2:2023 Broken Authentication** (CWE-347 Improper Verification of Cryptographic Signature / CWE-345).
- **Exploit:** `exploits/exploit_jwt_alg_none.py` forges an unsigned `alg:none` token for `sub="3"` and calls `GET /admin`: the vulnerable app returns `200`, the secure app `401`.
- **Fix:** `secure_app` pins `algorithms=["HS256"]` and never trusts the token's self-declared algorithm, so `alg:none` is rejected (`401`) before any role check. The flaw is scoped to the algorithm decision, so HS256 signature verification, legitimate auth, and the weak-secret demo are unchanged.

### Related robustness fix (both apps)

During JWT handling review, a related bug was found in both applications' `get_current_user()`: a token with a non-numeric `sub` claim could raise an unhandled `ValueError` when converted with `int()`, producing a `500 Internal Server Error`.

Both applications now catch this error alongside JWT decoding errors and return `401 Unauthorized`. This is a correctness fix, not a separate intentionally vulnerable category.

## Vulnerability Versus Security Control

The vulnerability demonstrations above are separate from the login rate-limiting control.

The secure application implements a limit of **5 login requests per minute per client IP** on `POST /login`. Excess requests receive HTTP `429 Too Many Requests`.

The vulnerable application intentionally does not apply this limit, preserving the vulnerable-versus-secure comparison. The current implementation uses an in-memory, IP-based limiter and is intended for this local learning lab, not as a complete production defense.

## Vulnerable vs. Secure Architecture

`vulnerable_app/` and `secure_app/` are completely separate FastAPI applications with separate Python packages, routers, authentication modules, and SQLite database files (`vulnerable.db` and `secure.db`).

Nothing is shared or toggled by a flag. This keeps the vulnerable implementation independent from the security fixes and allows a true side-by-side comparison.

## API Endpoints

Both applications expose the same core route surface, but their security behavior differs.

### `vulnerable_app` — http://127.0.0.1:8000

| Method | Path | Authentication | Behavior |
|---|---|---|---|
| GET | `/health` | No | Liveness check — `{"status": "ok"}`. **Vulnerable — Security Misconfiguration:** wide-open CORS (reflects any origin with credentials), no security headers |
| POST | `/login` | No | Verifies credentials and issues an HS256 JWT using the hardcoded `"supersecret"`; **Vulnerable — Brute Force:** no rate limit or lockout (unlimited attempts) |
| GET | `/users/{user_id}` | JWT required | **Vulnerable — BOLA/IDOR:** returns any user's data without an ownership check |
| PUT | `/users/{user_id}` | JWT required; ownership checked | **Vulnerable — Mass Assignment:** applies arbitrary request fields, including `role` |
| GET | `/admin` | JWT required | Checks the caller's role using the database record identified by the token's `sub`. **Vulnerable — alg:none:** accepts unsigned `alg:none` tokens, enabling forgery without the secret |
| GET | `/admin/users` | JWT required | **Vulnerable — BFLA + Unrestricted Resource Consumption:** no admin-role check, and returns the entire table with no pagination (ignores `limit`) |
| POST | `/orders` | JWT required | **Vulnerable — Improper Input Validation:** accepts a negative `quantity`/`unit_price` and persists a negative total |
| GET | `/orders/{order_id}` | JWT required; ownership checked | Returns the caller's own order, or any order for an admin; otherwise `403` |

### `secure_app` — http://127.0.0.1:8001

| Method | Path | Authentication | Behavior |
|---|---|---|---|
| GET | `/health` | No | Liveness check — `{"status": "ok"}`. **Fixed:** CORS allowlist (no wildcard) and security headers (`nosniff`, `DENY`/CSP `frame-ancestors`, `Referrer-Policy`) on every response |
| POST | `/login` | No | Verifies credentials, issues an HS256 JWT using `SECURE_APP_JWT_SECRET`, **rate-limits brute force** at 5 requests/minute per client IP (`429` after the 5th), **and locks an account** for 15 minutes after 5 consecutive failed passwords (generic `401` while locked) |
| GET | `/users/{user_id}` | JWT required | **Fixed:** permits access to the caller's own record or an admin; otherwise returns `403` |
| PUT | `/users/{user_id}` | JWT required; ownership checked | **Fixed:** permits only `username` and `email`; unexpected fields such as `role` return `422` |
| GET | `/admin` | JWT required | Requires the caller to have the `admin` role; pins `algorithms=["HS256"]`, so `alg:none`/forged tokens are rejected with `401` |
| GET | `/admin/users` | JWT required | **Fixed:** requires the `admin` role (`403` otherwise) and paginates results (`limit` 1–100 default 20, `offset` >= 0; invalid values `422`) |
| POST | `/orders` | JWT required | **Fixed:** requires positive `quantity`/`unit_price` and forbids unexpected fields; invalid input returns `422` |
| GET | `/orders/{order_id}` | JWT required; ownership checked | Returns the caller's own order, or any order for an admin; otherwise `403` |
 
## Project Structure

```text
fastapi-security-lab/
├── vulnerable_app/          # Intentionally insecure FastAPI app
│   ├── auth.py              # Password/JWT handling
│   ├── database.py          # SQLAlchemy engine/session
│   ├── main.py              # App entrypoint
│   ├── models.py            # SQLAlchemy models
│   ├── schemas.py           # Pydantic schemas
│   ├── seed_data.py         # Demo data
│   └── routers/
│       ├── login.py
│       ├── users.py
│       ├── admin.py
│       └── orders.py
├── secure_app/              # Hardened counterpart
│   ├── auth.py              # Secure JWT handling
│   ├── database.py
│   ├── main.py              # App and rate-limit configuration
│   ├── limiter.py           # Shared SlowAPI limiter
│   ├── models.py
│   ├── schemas.py
│   ├── seed_data.py
│   └── routers/
│       ├── login.py         # Login endpoint with rate limiting
│       ├── users.py
│       ├── admin.py
│       └── orders.py
├── exploits/                # Local exploit scripts
│   ├── exploit_bola.py
│   ├── exploit_mass_assignment.py
│   ├── exploit_weak_jwt.py
│   ├── exploit_improper_input_validation.py
│   ├── exploit_bfla.py
│   ├── exploit_unrestricted_resource_consumption.py
│   ├── exploit_brute_force.py
│   ├── exploit_account_lockout.py
│   ├── exploit_security_misconfiguration.py
│   └── exploit_jwt_alg_none.py
├── tests/
│   ├── conftest.py
│   ├── test_vulnerable_security.py
│   └── test_secure_security.py
├── docs/
│   ├── screenshots/
│   └── vulnerabilities/
├── evidence/                # Security testing evidence
├── requirements.txt
├── .gitignore
└── README.md
```

## Setup

Requires Python 3.11+; developed and tested on Python 3.12.

```bash
cd fastapi-security-lab

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

On Windows, create the virtual environment the same way (`python -m venv .venv`) but activate it with one of the following instead of the `source` command above, then install dependencies as shown:

```powershell
# Windows PowerShell
.venv\Scripts\Activate.ps1
```

```bat
:: Windows Command Prompt
.venv\Scripts\activate.bat
```

### Seed the databases

Each application has its own seed script and SQLite database. Run each script once before starting the corresponding server:

```bash
python -m vulnerable_app.seed_data
python -m secure_app.seed_data
```

Both scripts recreate their tables and insert three deterministic demo users for local testing:

| Username | Password | Role |
|---|---|---|
| `alice` | `alice_password123` | `user` |
| `bob` | `bob_password123` | `user` |
| `admin` | `admin_password123` | `admin` |

These are demo credentials for the isolated lab only. Never reuse them in a real system.

### Run `vulnerable_app` (port 8000)

```bash
uvicorn vulnerable_app.main:app --host 127.0.0.1 --port 8000
```

No extra configuration is required; the JWT secret is intentionally hardcoded in this application to demonstrate the weakness.

### Run `secure_app` (port 8001)

The secure application requires `SECURE_APP_JWT_SECRET` and refuses to start if the variable is missing or invalid.

Generate a strong secret and export it before starting the server:

```bash
export SECURE_APP_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
uvicorn secure_app.main:app --host 127.0.0.1 --port 8001
```

The secret is generated for local use and is not written to a file. Do not commit it to GitHub. If you keep a secret in a `.env` file for convenience, ensure `.env` remains excluded by `.gitignore`.

## Exploitation

The exploit scripts are local lab tools. Their request targets are configured for `http://127.0.0.1:8000`, the vulnerable application. Do not point them at systems you do not own or have permission to test.

With `vulnerable_app` running and seeded, open another terminal:

```bash
source .venv/bin/activate

python exploits/exploit_bola.py
python exploits/exploit_mass_assignment.py
python exploits/exploit_weak_jwt.py
python exploits/exploit_improper_input_validation.py
python exploits/exploit_bfla.py
python exploits/exploit_unrestricted_resource_consumption.py
python exploits/exploit_brute_force.py
python exploits/exploit_account_lockout.py
python exploits/exploit_security_misconfiguration.py
python exploits/exploit_jwt_alg_none.py
```

Each script uses the demo credentials, prints relevant request/response details, and ends with a `RESULT:` line explaining what it proved. Complete JWTs should not be printed or included in screenshots.

> **Reseed between demonstrations.** `exploit_mass_assignment.py` persistently changes Alice's role to `admin` in the vulnerable database. Later demonstrations that assume Alice has the ordinary `user` role — notably `exploit_weak_jwt.py`, whose baseline expects her legitimate token to be denied `/admin` with `403` — need the database reseeded first. Reseed with the existing command before rerunning them:
>
> ```bash
> python -m vulnerable_app.seed_data
> ```

### Choosing the target

By default every script targets `http://127.0.0.1:8000` — the vulnerable application. The target is resolved and safety-checked by `exploits/_target.py` when a script runs (inside `main()`), not when the module is imported, and always before any request is sent, with this precedence:

1. the `--target <url>` command-line argument;
2. the `EXPLOIT_TARGET` environment variable;
3. the default, `http://127.0.0.1:8000`.

The helper accepts **only loopback targets**: the host must be `127.0.0.1`, `localhost`, or `::1`, the scheme must be `http` or `https`, the URL must not embed credentials, and the port must be stated explicitly and be one of the two lab ports — **`8000` (vulnerable app)** or **`8001` (secure app)**. Any other host, port, or scheme is rejected with an error and a non-zero exit, before any network call. (The host is checked on the parsed hostname, so lookalikes such as `http://127.0.0.1.example.com:8000` are rejected.)

Examples (the existing invocation style still works unchanged):

```bash
# Default: the vulnerable app on port 8000
python exploits/exploit_bola.py

# Override for this run via the command-line argument
python exploits/exploit_bola.py --target http://127.0.0.1:8001

# Override via the environment variable (applies to each script you run)
EXPLOIT_TARGET=http://localhost:8000 python exploits/exploit_weak_jwt.py
```

Port `8000` is the vulnerable app and port `8001` is the secure app. These demonstrations are written for the **vulnerable** app: although the loopback guard permits `8001`, pointing an exploit at the secure app will not reproduce the vulnerable outcome — the secure app is built to resist these attacks, so a script may instead report that the attack failed (or behave differently) unless that script's own code explicitly handles the secure app. Use `8001` only when you specifically want to observe the secure app's defensive behavior, not as a drop-in substitute for the vulnerable target.

## Security Fixes

| Finding or control | Fix or behavior |
|---|---|
| BOLA / IDOR | `secure_app` checks object-level authorization on `GET /users/{user_id}` and returns `403` for unauthorized cross-user access. |
| Mass Assignment | `secure_app` allows only `username` and `email` during profile updates and rejects unexpected fields such as `role` with `422`. An empty `username` is also rejected with `422` (`min_length=1`), and a duplicate `username`/`email` is handled at commit with a rollback and `409 Conflict` (generic message, no DB details). |
| Weak JWT Secret | `secure_app` reads the signing secret from `SECURE_APP_JWT_SECRET`, enforces a minimum length, and refuses to start if the secret is missing or too short. |
| Non-numeric JWT `sub` claim | Both applications return `401` rather than an unhandled `500` when the subject claim cannot be converted to an integer. |
| Login rate limiting | `secure_app` limits `POST /login` to 5 requests per minute per client IP. Excess requests return `429 Too Many Requests`. |

## Automated Security Tests

The suite is in `tests/` and is split by intent:

- **`tests/test_vulnerable_security.py`** intentionally asserts the vulnerable behavior. For example, a BOLA test confirms that Alice's token can retrieve Bob's record with `200 OK`. This documents the intended flaw rather than representing a test defect.
- **`tests/test_secure_security.py`** verifies secure behavior, including `403` for unauthorized cross-user access, `422` for an unexpected `role` field, and `429` after excessive login attempts.
- **`tests/conftest.py`** provides test configuration, including a strong test-only `SECURE_APP_JWT_SECRET`, so the secure application can be imported without weakening its startup validation.

Run the full suite from the repository root:

```bash
python -m pytest tests/ -v
```

> **The full suite rewrites the real demo databases.** `tests/test_vulnerable_security.py` and `tests/test_secure_security.py` use autouse fixtures that call each app's seed routine before every test, which drops, recreates, and reseeds `vulnerable_app/vulnerable.db` and `secure_app/secure.db` in place. Running the full suite therefore discards any local state in those databases (for example, a role an exploit demonstration left behind) and resets both to their seeded demo data. Run it only when that is acceptable; to exercise a single area without resetting the databases, run a specific test file or node instead (e.g. `python -m pytest tests/test_secure_startup_config.py -v`).

**Previously recorded full-suite result: 96 passed** — an earlier, historical figure. During this integration the full suite was rerun against an *isolated copy* of the repository (so the real demo databases, which the autouse fixtures drop and reseed in place, were left untouched): **136 passed, 34 warnings**. The higher count reflects the security demos added since the 96-pass run; the warnings are expected (notably the vulnerable app's intentionally weak `"supersecret"` signing key triggering PyJWT's `InsecureKeyLengthWarning`, plus Starlette/httpx deprecations). The focused test files covering the integrated changes also pass on their own (40 passed, 1 warning). Because the full suite resets the demo databases in place, run it from the repo root deliberately; individual test files can be run on their own without resetting the databases.

The login rate-limit regression test checks that the first five invalid login attempts return `401 Unauthorized` and the sixth returns `429 Too Many Requests` within the configured limit window. The test suite uses FastAPI's `TestClient`; no external service is required.

## Manual Security Testing

The applications can also be tested manually using `curl` or Burp Suite Community Edition.

Examples of behaviors demonstrated during testing:

- **BOLA:** Alice's token retrieves Bob's record from the vulnerable app with `200`; the secure app denies the same cross-user request with `403`.
- **Mass Assignment:** Alice can change her role to `admin` in the vulnerable app; the secure app rejects the extra `role` property with `422` and leaves her role unchanged.
- **Function-level authorization:** Alice receives `403` from the secure `/admin` endpoint, while a valid admin account receives `200`.
- **Login rate limiting:** The first five invalid login attempts return `401`; subsequent attempts during the rate-limit window return `429`.

Use only the local applications and demo credentials when reproducing these results. Redact bearer tokens and other secrets from screenshots before publishing evidence.

## Learning Outcomes

This project practices and demonstrates:

- The difference between **authentication** (who you are) and **authorization** (what you are allowed to do).
- **BOLA/IDOR:** why object-level authorization must be checked on every relevant request.
- **Mass assignment:** why request schemas need explicit allowlists instead of trusting arbitrary client-supplied fields.
- **JWT security fundamentals:** how hardcoded or weak signing secrets undermine token integrity.
- **Secure secret management:** loading secrets from the environment and refusing to start when security requirements are not met.
- **Rate limiting:** restricting repeated login attempts and testing the `429 Too Many Requests` response.
- **Negative security testing:** proving that an attack fails against the secure implementation.
- **Controlled exploit development:** writing small scripts that target only the local vulnerable application.
- **Security regression testing:** encoding expected security behavior as repeatable automated tests.
- **Manual API testing:** using HTTP requests and Burp Suite to inspect and compare vulnerable and secure behavior.

## Limitations / Current Scope

- The project demonstrates ten security topics in depth: BOLA/IDOR, mass assignment, weak JWT signing secrets, improper input validation, broken function-level authorization, unrestricted resource consumption, brute-force authentication, account lockout, security misconfiguration (CORS and headers), and a JWT algorithm-verification flaw (alg:none).
- Rate limiting is implemented only on `secure_app`'s `POST /login` endpoint, at 5 requests per minute per client IP. The vulnerable application intentionally remains unrestricted, and other endpoints are not rate-limited.
- The current rate limiter is in-memory and IP-based. It is appropriate for this local learning lab but is not a complete production defense against distributed brute-force attempts or resource exhaustion.
- Additional authentication scenarios, such as password-strength enforcement and credential-stuffing defenses, are not implemented. (Account lockout is implemented — see the Account Lockout report.)
- The `/orders` API demonstrates improper input validation (`POST /orders`) and enforces object-level authorization on retrieval (`GET /orders/{order_id}`); see the Orders API report for details.
- There is no separate `/profile` API. Profile viewing and updating are handled through `GET` and `PUT /users/{user_id}`.

This project does not claim to cover the entire OWASP API Security Top 10. It focuses on a smaller set of high-impact issues, with explicit vulnerable behavior, remediation, and testing.

## Future Extensions

Possible future improvements include:

- Compare the current JWT implementation with OAuth2/OIDC-based authentication.
- Expand OWASP API Security Top 10 coverage.
- Add more documented Burp Suite testing walkthroughs.
- Extend CI security checks further (for example static analysis / code scanning and a coverage gate) on top of the dependency audit (`pip-audit`) now run on every push.
- Explore a shared rate-limit backend for multi-worker or distributed deployments.

## Disclaimer

This project is intentionally vulnerable and built strictly for local, authorized security education and self-testing. It is not production software, has not undergone professional security review, and must not be deployed as-is to a public environment. Never reuse the vulnerable application's code, secrets, or security patterns in a real system.
