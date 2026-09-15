# Weak JWT Secret

## Overview

`vulnerable_app` signs and verifies all JWTs with a hardcoded,
short, guessable secret defined directly in the application source:
`JWT_SECRET_KEY = "supersecret"` (HS256). Because this project's source
is intended for a public GitHub repository, that secret is effectively
public. Anyone who knows it can create their own validly-signed JWTs
completely offline, with no interaction with the server, no password,
and no session theft required.

**This document deliberately describes the exact, confirmed mechanism
of the exploit** — including a specific detail that makes the attack
*less naive* than "just set role to admin," but no less severe.

## Affected Endpoint / Component

- **Component:** JWT signing and verification, `vulnerable_app/auth.py`
- **Demonstrated against:** `GET /admin`
- **Application affected:** `vulnerable_app` (fixed in `secure_app`)

## Vulnerable Behavior

```python
JWT_SECRET_KEY = "supersecret"
JWT_ALGORITHM = "HS256"
```

`get_current_user()` decodes the JWT, then looks up the *real* user
record in the database using the token's `sub` claim, and returns that
database record:

```python
payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
user_id = payload.get("sub")
...
user = db.query(User).filter(User.id == user_id).first()
return user
```

`GET /admin` then checks `current_user.role`, which is the value just
loaded from the database — **not** a value read directly out of the
token payload:

```python
if current_user.role != "admin":
    raise HTTPException(status_code=403, detail="Admin access required")
```

**This detail matters and must not be oversimplified.** Because `role`
in `/admin`'s authorization check comes from the database lookup keyed
on `sub`, forging a token with `sub="1"` (Alice's real database ID) and
`role="admin"` does **not** grant admin access — the server still looks
up Alice's real row and finds her real role, `"user"`. Simply changing
the `role` claim in a forged token, while leaving `sub` pointed at a
non-admin account, has no effect on this endpoint.

The actual vulnerability is broader and more serious than that: because
`sub` is a JWT claim like any other, and the entire token is signed with
a known secret, an attacker can forge a token with `sub` set to the
**real admin account's database ID** instead. The server has no way to
distinguish this forged token from one genuinely issued by `/login` to
the real admin — both are validly signed under `JWT_SECRET_KEY`. The
result is full impersonation of the admin account, not a spoofed claim
being blindly trusted.

## Exploitation

`exploits/exploit_weak_jwt.py` demonstrates this precisely, in the
order the script actually runs:

1. **Legitimate baseline.** Logs in as Alice with real credentials via
   `POST /login`, obtains a real token, and confirms `GET /admin` with
   that real token correctly returns `403` (Alice is a genuine `"user"`
   role account).
2. **Forged token, `sub="1"`, `role="admin"`.** Builds and signs a new
   JWT from scratch with `KNOWN_WEAK_SECRET = "supersecret"`, containing
   `sub="1"` (Alice's real ID) and `role="admin"`. Sends this to
   `GET /admin`. The script's own recorded output notes this attempt
   still returns `403`, and explains why: `get_current_user()` re-reads
   Alice's role from the database by `sub`, so the forged `role` claim
   in the payload is never consulted.
3. **Forged token, `sub="3"` (the seeded admin's real database ID).**
   Builds and signs a second JWT, this time with `sub="3"` — the
   database ID of the `admin` account created by `seed_data.py` — along
   with `role="admin"`. Sends this to `GET /admin`. This request
   succeeds with HTTP `200` and the response
   `{"message": "Welcome to the admin area"}`, because the server looks
   up user ID 3, which genuinely has `role: "admin"` in the database.
4. Prints a `RESULT: VULNERABLE` summary explaining that the attacker
   never needed the admin's password, and that impersonation worked
   through `sub`, not through the `role` claim being trusted directly.

The exact same finding is pinned by
`tests/test_vulnerable_security.py::TestVulnerableWeakJWT::test_forged_token_with_known_secret_grants_admin`,
which forges a token with `sub="3"` (matching the exploit script) and
asserts `200` with the `"Welcome to the admin area"` message — not a
token with `sub="1", role="admin"`, consistent with the confirmed
mechanism above.

This is a local lab demonstration only, run against
`http://127.0.0.1:8000` using the deterministic demo accounts created
by `vulnerable_app/seed_data.py`.

## Impact

In a real API, a hardcoded or otherwise-known JWT signing secret is a
complete authentication bypass, not merely a weak-password-style risk.
An attacker who obtains the secret (through source code exposure, a
leaked config file, a public repository, or a guessable value) can
impersonate **any user account, including the highest-privileged
administrator account**, without ever needing that account's password,
interacting with the login flow as that user, or stealing an active
session. The blast radius of a leaked signing secret is every account
in the system, indefinitely, until the secret is rotated.

## OWASP Mapping

**OWASP API Security Top 10 — API2:2023: Broken Authentication.** The
signing secret underpinning the entire JWT trust model is weak,
hardcoded, and never rotated, which breaks the integrity guarantee that
authentication is supposed to provide: a valid signature no longer
reliably proves "issued by this server's real `/login` flow." This
finding is specifically about **token/secret integrity**, not about a
missing or misused `role` claim — the authorization logic on `/admin`
(checking `current_user.role`) is not itself flawed; it is undermined
by an attacker's ability to forge the identity (`sub`) the authorization
check relies on.

## Evidence

Confirmed via the exploit script and the automated test suite (not a
screenshot or fabricated log):

- Alice's real, legitimately-issued token correctly receives `403` from
  `GET /admin`.
- A token forged with the known secret `"supersecret"`, `sub="1"`
  (Alice's ID), `role="admin"`, also receives `403` — confirming `role`
  alone is not trusted.
- A token forged with the same known secret, `sub="3"` (the real admin's
  database ID), receives `200` with
  `{"message": "Welcome to the admin area"}` — confirming full admin
  impersonation via a forged identity claim.

This is confirmed by `exploits/exploit_weak_jwt.py`'s printed output and
the passing assertion in `test_forged_token_with_known_secret_grants_admin`.
No full tokens or the real signing secret value beyond the intentionally
documented `"supersecret"` are included in this document; no output was
invented beyond what the script and test actually produce.

## Remediation

`secure_app/auth.py` fixes this by removing any hardcoded or default
secret entirely:

```python
JWT_SECRET_KEY = os.environ.get("SECURE_APP_JWT_SECRET")

if not JWT_SECRET_KEY:
    raise RuntimeError("SECURE_APP_JWT_SECRET environment variable is not set. ...")

if len(JWT_SECRET_KEY) < _MIN_SECRET_LENGTH:  # 32 characters
    raise RuntimeError("SECURE_APP_JWT_SECRET is only ... characters long; refusing to start ...")
```

- The secret is supplied **only** through the `SECURE_APP_JWT_SECRET`
  environment variable — never hardcoded, never committed to source.
- A minimum length (32 characters) is enforced.
- If the variable is missing or too short, the application **fails
  fast**: it raises at import time and refuses to start, rather than
  silently falling back to any default (weak, guessable, or otherwise).
- Signature verification (`jwt.decode(token, JWT_SECRET_KEY,
  algorithms=[JWT_ALGORITHM])`) then only accepts tokens signed with
  this real, unknown-to-attackers secret — a token forged with
  `"supersecret"` fails signature verification and is rejected with
  `401` before any `sub`/role logic is reached at all.

**Related robustness fix (both apps):** `get_current_user()` in both
`vulnerable_app/auth.py` and `secure_app/auth.py` now catches
`ValueError` alongside JWT decoding errors when converting the `sub`
claim to an integer. Previously, a token with a non-numeric `sub` raised
an unhandled `ValueError`, producing a raw `500 Internal Server Error`;
it now correctly returns `401 Unauthorized`, like any other malformed
token. This is a general input-handling correctness fix for the
authentication dependency, not specific to the weak-secret vulnerability
itself.

## Secure Verification

`tests/test_secure_security.py::TestSecureWeakJWTProtection` verifies
the fix directly:

- `test_alice_legitimate_token_cannot_access_admin` — confirms Alice's
  real, legitimately-issued token still correctly receives `403`.
- `test_token_forged_with_vulnerable_secret_is_rejected` — forges a
  token with `sub="3"` signed using the vulnerable app's known secret
  (`"supersecret"`) and confirms `secure_app` rejects it with `401`,
  never reaching the admin role check at all.

`tests/test_secure_security.py::TestGetCurrentUserRobustness::test_non_numeric_sub_returns_401_not_500`
additionally verifies the related non-numeric-`sub` fix, using a token
signed with `secure_app`'s own real secret.

## Vulnerable vs Secure

| Aspect | Vulnerable App | Secure App |
|---|---|---|
| Signing secret | Hardcoded in source: `"supersecret"` | Read only from `SECURE_APP_JWT_SECRET`; never hardcoded |
| Missing/weak secret handling | N/A — secret is always present and fixed | App refuses to start (`RuntimeError`) if missing or under 32 characters |
| Forged token, `sub="1"`, `role="admin"` (Alice's ID) | `403` — role re-derived from DB, forged claim ignored | N/A — signature fails first |
| Forged token, `sub="3"` (real admin's ID), signed with `"supersecret"` | `200` — full admin impersonation | `401` — signature verification fails; server secret differs |
| Non-numeric `sub` claim | `401` (fixed; previously `500`) | `401` (fixed; previously `500`) |

## Interview Takeaway

- Why a JWT signature only proves "signed with this key," not "issued
  by the real login flow" — the security of the entire scheme reduces
  to the secrecy of one value.
- Why hardcoding a signing secret in source code is catastrophic once
  that source becomes public (or is ever leaked), regardless of how
  "obscure" the value looks.
- Why this specific finding is about identity forgery via `sub`, not
  about a `role` claim being blindly trusted — and why getting that
  distinction right matters when explaining a real finding accurately.
- Why "fail fast" (refusing to start without a proper secret) is safer
  than silently falling back to any default, even a randomly generated
  one, because it forces a conscious configuration decision rather than
  letting a misconfiguration pass unnoticed.
- Why secrets belong in environment variables / secrets managers, never
  in version-controlled source files.
