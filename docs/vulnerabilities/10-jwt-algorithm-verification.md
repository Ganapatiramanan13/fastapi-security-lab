# JWT Algorithm-Verification Flaw (alg:none)

## Overview

`vulnerable_app`'s token verifier (`vulnerable_app/auth.py:get_current_user`)
trusts the algorithm the **token declares in its own header** instead of
pinning a single expected algorithm. When a token's header says
`alg: "none"`, the verifier accepts it **without any signature check**. An
attacker can therefore forge a token for any user id — including the
administrator — **without knowing the signing secret at all**. `secure_app`
pins `algorithms=["HS256"]` and rejects such tokens.

> **This is an intentionally introduced educational vulnerability.** Before
> this stage, *both* apps pinned `algorithms=["HS256"]` and were already
> immune to `alg:none` / algorithm confusion. This stage deliberately adds
> the flaw to the vulnerable app to demonstrate the attack; it is not a claim
> that the application was already vulnerable.

## Relationship to the weak-JWT-secret demonstration

This is distinct from, and complementary to, the Weak JWT Secret finding
(report 03):

- **Weak secret (report 03):** the attacker must obtain the signing secret
  (here it was hardcoded) and then *signs* a valid HS256 token with it. A
  strong, secret key defeats that attack.
- **alg:none (this report):** the attacker needs **no secret at all** — the
  server never verifies a signature for an `alg:none` token. A strong secret
  does **not** help, because the signature is never checked. The fix is to
  pin the accepted algorithms, not merely to protect the key.

## Affected Component

- **Component:** JWT verification, `vulnerable_app/auth.py` (`get_current_user`).
- **Demonstrated against:** `GET /admin`.
- **Application affected:** `vulnerable_app` (secure in `secure_app`).

## Preconditions

- Network access to a protected endpoint and knowledge of the target user's
  id (the seeded admin's id is `3`; ids are easily enumerable, e.g. via the
  BOLA finding). No signing secret, password, or session is required.
- The vulnerable app is running and seeded locally (`http://127.0.0.1:8000`).

## Vulnerability Description

The verifier reads the token's unverified header and branches on the
self-declared algorithm:

```python
# vulnerable_app/auth.py (intentional flaw)
if jwt.get_unverified_header(token).get("alg") == "none":
    payload = jwt.decode(
        token,
        algorithms=["none"],
        options={
            "verify_signature": False,
            "verify_exp": True,
            "verify_nbf": True,
            "require": ["exp"],
        },
    )
else:
    payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
```

For `alg:none` the signature is not verified, so any attacker-chosen claims
are trusted. The rest of the flow is unchanged: `sub` is read, converted to
an int, and used to load the user from the database; `GET /admin` then
checks that user's DB `role`. Because the attacker sets `sub="3"` (the real
admin row), the loaded user genuinely has `role="admin"`, so the admin check
passes — full impersonation.

**The flaw is scoped to signature verification only.** A normal HS256 token
is still verified against `JWT_SECRET_KEY`, and on the `alg:none` path the
**time-based claim checks are deliberately kept on** (`verify_exp`,
`verify_nbf`, and `exp` is required) — only the signature check is disabled.
So an expired or not-yet-valid (`nbf`) unsigned token is rejected, and a
forged token still needs a valid `exp`; the bypass is strictly "no signature
required," not "no claim validation." (Other claims such as `role` are still
attacker-controlled, but authorization re-derives the role from the database
row named by `sub`, so that is not an additional escalation.) This is
confirmed by tests: legitimate HS256 login tokens still work, an HS256 token
signed with the wrong secret is still rejected (`401`), and expired /
future-`nbf` / missing-`exp` unsigned tokens are all rejected (`401`).

## Reproduction Steps

With the vulnerable app seeded and running on `127.0.0.1:8000`:

1. Build an **unsigned** JWT (`alg:none`) with `sub="3"`, `role="admin"` —
   no secret used.
2. Send it as `Authorization: Bearer <token>` to `GET /admin`.

`exploits/exploit_jwt_alg_none.py` does exactly this (localhost-only). It
first confirms Alice's real token gets `403`, then shows the forged
`alg:none` token getting `200` on the vulnerable app and `401` on the secure
app. The behavior is pinned by
`tests/test_vulnerable_security.py::TestVulnerableJwtAlgNone` and
`tests/test_secure_security.py::TestSecureJwtAlgNoneProtection`.

## Actual Responses (verified)

| Request | Vulnerable (`:8000`) | Secure (`:8001`) |
|---|---|---|
| Alice's real HS256 token → `/admin` | `403` | `403` |
| Unsigned `alg:none` token (`sub=3`) → `/admin` | **`200` "Welcome to the admin area"** | **`401` "Could not validate credentials"** |
| HS256 token signed with the WRONG secret → `/admin` | `401` (signature still enforced) | `401` |

## Security Impact

Accepting `alg:none` is a **complete authentication bypass**: an attacker can
impersonate any user, including the administrator, with no secret, no
password, and no stolen session — just a forged, unsigned token and a known
or guessed user id. Unlike a leaked secret (which can be rotated), this flaw
cannot be mitigated by key strength or rotation; only correct algorithm
pinning fixes it.

## Severity Assessment

**Severity: Critical.** Rationale: trivial to exploit (craft one unsigned
token), requires no secret/credential, and yields full account/admin
impersonation. It is more severe than the weak-secret finding because it does
not depend on obtaining any secret. No CVSS score is asserted; the rating
reflects the lab's isolated behavior.

## OWASP API Security Top 10 and CWE Mapping

- **OWASP API Security Top 10 — API2:2023: Broken Authentication.** The token
  verification does not correctly enforce the signing algorithm, so forged
  tokens are accepted.
- **CWE-347: Improper Verification of Cryptographic Signature** — the primary
  mapping: the server fails to verify the token's signature for `alg:none`.
- Related: **CWE-345 (Insufficient Verification of Data Authenticity)**.

## Secure Implementation and Remediation

`secure_app/auth.py` is unchanged and already correct:

```python
payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])  # ["HS256"]
```

- **Pin the accepted algorithm(s) explicitly** and never include `"none"`.
  Never derive the verification algorithm from the token's own header.
- With `algorithms=["HS256"]`, PyJWT raises `InvalidAlgorithmError` for an
  `alg:none` token (verified with PyJWT 2.15.1), so it is rejected with a
  generic `401` before any `sub`/role logic runs.
- For asymmetric setups, pinning also prevents the RS256→HS256 confusion
  attack (verifying an RS256 token's signature using the public key as an
  HMAC secret). Keep signing and verification algorithms fixed and separate.

## PyJWT behavior (verified, not assumed)

On the installed **PyJWT 2.15.1**:
- `jwt.decode(none_token, algorithms=["HS256"])` → `InvalidAlgorithmError`
  (secure app path — rejected).
- Adding `"none"` to the allowlist with a key → `InvalidKeyError`
  (`"When alg = none, key value must be None"`). An `alg:none` token is only
  accepted via `options={"verify_signature": False}`, which is exactly the
  unsafe branch the vulnerable app uses.
- A legitimate HS256 token still verifies normally alongside the above.
- **Important:** `options={"verify_signature": False}` *alone* ALSO disables
  `exp` and `nbf` validation in PyJWT 2.15.1 (verified: an expired or
  future-`nbf` unsigned token would be accepted). The vulnerable path
  therefore passes `{"verify_signature": False, "verify_exp": True,
  "verify_nbf": True, "require": ["exp"]}` to keep those time-based checks
  ON while leaving the signature flaw intentionally present
  (`ExpiredSignatureError` / `ImmatureSignatureError` /
  `MissingRequiredClaimError` — each becomes a clean 401).

## Validation and Regression-Test Results

- `tests/test_vulnerable_security.py::TestVulnerableJwtAlgNone`: an `alg:none`
  token (`sub=3`, valid `exp`) grants admin (`200`); an **expired** unsigned
  token and a **future-`nbf`** unsigned token are both rejected (`401`),
  proving time-based claim validation is preserved on this path; an HS256
  token with the wrong secret is still rejected (`401`, proving the flaw is
  scoped to signature, not global); a real login token still works; a
  non-numeric `sub` on the `alg:none` path still returns `401` (malformed
  handling preserved).
- `tests/test_secure_security.py::TestSecureJwtAlgNoneProtection`: the secure
  app rejects the `alg:none` token (`401`) and still accepts a real admin
  token (`200`).
- The existing weak-secret demonstration (report 03) and all other tests are
  unchanged and still pass.
- Full suite result at the time of writing: **96 passed** (see the README).

## Evidence

The following are rendered terminal-style images generated from the actual
output of `exploits/exploit_jwt_alg_none.py` against the local apps (they are
rendered captures of real output, not native terminal screenshots):

- `evidence/28-jwt-alg-none-vulnerable.png` — the vulnerable app (`:8000`):
  the forged `alg:none` token (header `{"alg":"none"}`) returns `200`
  "Welcome to the admin area".
- `evidence/29-jwt-alg-none-secure.png` — the secure app (`:8001`): the same
  token returns `401` "Could not validate credentials".

## Evidence Limitations

The images are rendered terminal-style captures of the exploit's real stdout,
not native screenshots. Tokens are shown as a short prefix only; no passwords
or secrets appear (the attack uses no secret). The demo targets only the
loopback interface over http/https and uses only the lab's `/login` and
`/admin` endpoints.

## Interview Takeaway

- Why `alg:none` is catastrophic: it lets the attacker choose "no signature,"
  so the server trusts arbitrary claims — a full auth bypass with no key.
- Why algorithm pinning (not key strength) is the fix: a strong secret does
  nothing if the signature is never checked.
- Why you must never trust the token's self-declared `alg`: the header is
  attacker-controlled; the server must fix the accepted algorithm(s).
- How this complements the weak-secret finding: one needs the key, the other
  needs no key — both are "Broken Authentication," fixed in different ways.
