# FastAPI Security Lab
## Vulnerability Reports

Detailed write-ups document each vulnerability, its root cause, reproduction steps, security impact, remediation, and verification.

1. [BOLA / IDOR — Broken Object Level Authorization](docs/vulnerabilities/01-bola-idor.md)
2. [Mass Assignment — Unauthorized Role Modification](docs/vulnerabilities/02-mass-assignment.md)
3. [Weak JWT Secret — Token Forgery and Account Impersonation](docs/vulnerabilities/03-weak-jwt.md)
4. [Improper Input Validation — Orders API](docs/vulnerabilities/04-improper-input-validation.md)

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

Three vulnerability categories are intentionally implemented in the vulnerable application, each with a vulnerable endpoint or component, a secure fix, an exploit script, and automated tests.

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

### Related robustness fix (both apps)

During JWT handling review, a related bug was found in both applications' `get_current_user()`: a token with a non-numeric `sub` claim could raise an unhandled `ValueError` when converted with `int()`, producing a `500 Internal Server Error`.

Both applications now catch this error alongside JWT decoding errors and return `401 Unauthorized`. This is a correctness fix, not a separate intentionally vulnerable category.

## Vulnerability Versus Security Control

The three vulnerability demonstrations above are separate from the login rate-limiting control.

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
| GET | `/health` | No | Liveness check — `{"status": "ok"}` |
| POST | `/login` | No | Verifies credentials and issues an HS256 JWT using the hardcoded `"supersecret"` |
| GET | `/users/{user_id}` | JWT required | **Vulnerable — BOLA/IDOR:** returns any user's data without an ownership check |
| PUT | `/users/{user_id}` | JWT required; ownership checked | **Vulnerable — Mass Assignment:** applies arbitrary request fields, including `role` |
| GET | `/admin` | JWT required | Checks the caller's role using the database record identified by the token's `sub` |
| POST | `/orders` | JWT required | **Vulnerable — Improper Input Validation:** accepts a negative `quantity`/`unit_price` and persists a negative total |
| GET | `/orders/{order_id}` | JWT required; ownership checked | Returns the caller's own order, or any order for an admin; otherwise `403` |

### `secure_app` — http://127.0.0.1:8001

| Method | Path | Authentication | Behavior |
|---|---|---|---|
| GET | `/health` | No | Liveness check — `{"status": "ok"}` |
| POST | `/login` | No | Verifies credentials, issues an HS256 JWT using `SECURE_APP_JWT_SECRET`, and enforces 5 requests per minute per client IP |
| GET | `/users/{user_id}` | JWT required | **Fixed:** permits access to the caller's own record or an admin; otherwise returns `403` |
| PUT | `/users/{user_id}` | JWT required; ownership checked | **Fixed:** permits only `username` and `email`; unexpected fields such as `role` return `422` |
| GET | `/admin` | JWT required | Requires the caller to have the `admin` role |
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
│   └── exploit_improper_input_validation.py
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
```

Each script uses the demo credentials, prints relevant request/response details, and ends with a `RESULT:` line explaining what it proved. Complete JWTs should not be printed or included in screenshots.

## Security Fixes

| Finding or control | Fix or behavior |
|---|---|
| BOLA / IDOR | `secure_app` checks object-level authorization on `GET /users/{user_id}` and returns `403` for unauthorized cross-user access. |
| Mass Assignment | `secure_app` allows only `username` and `email` during profile updates and rejects unexpected fields such as `role` with `422`. |
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

**Latest recorded result: 41 passed.**

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

- The project intentionally demonstrates three vulnerability categories in depth: BOLA/IDOR, mass assignment, and weak JWT signing secrets.
- Rate limiting is implemented only on `secure_app`'s `POST /login` endpoint, at 5 requests per minute per client IP. The vulnerable application intentionally remains unrestricted, and other endpoints are not rate-limited.
- The current rate limiter is in-memory and IP-based. It is appropriate for this local learning lab but is not a complete production defense against distributed brute-force attempts or resource exhaustion.
- Additional authentication scenarios, such as account lockout, password-strength enforcement, and credential-stuffing defenses, are not implemented.
- The `/orders` API demonstrates improper input validation (`POST /orders`) and enforces object-level authorization on retrieval (`GET /orders/{order_id}`); see the Orders API report for details.
- There is no separate `/profile` API. Profile viewing and updating are handled through `GET` and `PUT /users/{user_id}`.

This project does not claim to cover the entire OWASP API Security Top 10. It focuses on a smaller set of high-impact issues, with explicit vulnerable behavior, remediation, and testing.

## Future Extensions

Possible future improvements include:

- Add a dedicated vulnerable-versus-secure demonstration for unrestricted resource consumption.
- Compare the current JWT implementation with OAuth2/OIDC-based authentication.
- Expand OWASP API Security Top 10 coverage.
- Add more documented Burp Suite testing walkthroughs.
- Extend the existing CI workflow (which already runs pytest on every push) to also perform dependency vulnerability scanning.
- Explore a shared rate-limit backend for multi-worker or distributed deployments.

## Disclaimer

This project is intentionally vulnerable and built strictly for local, authorized security education and self-testing. It is not production software, has not undergone professional security review, and must not be deployed as-is to a public environment. Never reuse the vulnerable application's code, secrets, or security patterns in a real system.
