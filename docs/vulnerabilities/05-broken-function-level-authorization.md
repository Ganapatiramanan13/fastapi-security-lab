# Broken Function Level Authorization (BFLA)

## Overview

`vulnerable_app` exposes `GET /admin/users`, an administrative function
that lists every user account. The endpoint verifies that the caller is
*authenticated* (a valid JWT via `get_current_user`) but never verifies
that the caller is *authorized* for this administrative function — it never
checks the `admin` role. As a result, any ordinary logged-in user can call
the endpoint and enumerate every account (usernames, emails, roles). This
is a textbook Broken Function Level Authorization (BFLA): authentication is
enforced, but function-level authorization is missing.

This is distinct from the project's existing BOLA finding (object-level
authorization — "can this user access *this specific record*?") and its
mass-assignment finding (property-level authorization — "can this user set
*this field*?"). BFLA is function-level: "is this user allowed to invoke
*this operation at all*?"

## Affected Endpoint

- **Method:** `GET`
- **Endpoint:** `/admin/users`
- **Application affected:** `vulnerable_app` (fixed in `secure_app`)
- **Unchanged:** the existing `GET /admin` endpoint, which already performs
  a correct role check in both apps, is left exactly as it was.

## Preconditions

- The caller is authenticated with a valid JWT for any ordinary user (no
  admin rights, no token forgery, no special tooling).
- The vulnerable app is running and seeded locally
  (`http://127.0.0.1:8000`).

## Vulnerability Description

`vulnerable_app/routers/admin.py` adds:

```python
@router.get("/admin/users", response_model=list[UserOut])
def list_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # No role check here — authentication is treated as sufficient.
    return db.query(User).all()
```

`get_current_user` only proves the token is a validly signed JWT for some
user; it does not decide what that user may do. The existing `GET /admin`
endpoint guards itself with `if current_user.role != "admin": 403`, but
that guard was simply not repeated on this new administrative function.
Every endpoint must make its own function-level authorization decision;
omitting it on one endpoint is enough to expose it.

The response schema is `UserOut`, which never includes `password_hash`, so
the finding is strictly the missing authorization on a privileged function,
not sensitive-field leakage.

## Reproduction Steps

With the vulnerable app seeded and running on `127.0.0.1:8000`:

1. Log in as Alice (`alice` / `alice_password123`, role `user`) via
   `POST /login` and obtain a valid token.
2. Call `GET /admin/users` with Alice's token.

`exploits/exploit_bfla.py` performs exactly these steps (defaulting to the
vulnerable app, with a localhost-only target guard) and prints a `RESULT`
line. The same behavior is pinned by
`tests/test_vulnerable_security.py::TestVulnerableBrokenFunctionLevelAuth`.

## Vulnerable vs Secure HTTP Responses

| Request | Vulnerable (`:8000`) | Secure (`:8001`) |
|---|---|---|
| `GET /admin/users` as Alice (role `user`) | `200` + full user list | `403 Admin access required` |
| `GET /admin/users` as admin | `200` + full user list | `200` + full user list |
| `GET /admin/users` with no token | `401` | `401` |
| `GET /admin/users` with an invalid token | `401` | `401` |

Actual vulnerable response (ordinary user):

```
HTTP status code: 200
Users returned: 3 -> ['alice', 'bob', 'admin']
```

## Security Impact

An ordinary, low-privilege account can invoke an administrative function
and enumerate every user in the system — a direct confidentiality breach
(account inventory, emails, roles) and a reconnaissance primitive for
further attacks (for example, identifying the admin account's id for a
targeted follow-up). In a real API, the same flaw on a *state-changing*
admin function (delete a user, change a role, refund an order) would allow
privilege escalation or data destruction by any logged-in user. Broken
function-level authorization is consistently among the most common and
highest-impact API findings precisely because the endpoints look ordinary
and are easy to miss when only authentication is tested.

## Severity Assessment

**Severity: High.** Rationale: exploitation is trivial (a single
authenticated request from any ordinary account, no special privileges or
tooling), and the impact is unauthorized access to an administrative
function exposing all users' data. It is rated High rather than Critical
because, as implemented here, the exposed function is read-only
(enumeration) rather than state-changing, and no credentials or password
hashes are disclosed. No CVSS score is asserted; the rating reflects the
lab's isolated behavior (trivial trigger, broad unauthorized read of
account data) rather than a calculated vector.

## OWASP API Security Top 10 Mapping

**OWASP API Security Top 10 — API5:2023: Broken Function Level
Authorization.** The API enforces authentication but fails to enforce the
role/function-level authorization required to invoke an administrative
operation. This is explicitly a *function-level* authorization failure, not
object-level (API1) or property-level (API3); mapping it to those
categories would misrepresent the root cause.

## CWE Mapping

- **CWE-285: Improper Authorization** — the software does not perform (or
  incorrectly performs) an authorization check for the administrative
  function, allowing a user to access functionality their role should not
  permit.
- Related: **CWE-862: Missing Authorization** — the authorization check is
  absent entirely on this endpoint.

## Secure Implementation and Remediation

`secure_app/routers/admin.py` enforces the function-level check that the
vulnerable app omits:

```python
@router.get("/admin/users", response_model=list[UserOut])
def list_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return db.query(User).all()
```

- Only a caller whose role is `admin` may invoke the endpoint; every other
  authenticated caller receives `403` **before** any user data is read.
- Authentication alone is never treated as sufficient for a privileged
  function.
- The response schema remains `UserOut` (no `password_hash`).

**Prevention (general):** enforce authorization on every endpoint, not just
authentication; prefer a centralized/declarative role or permission
dependency (for example a reusable `require_admin` dependency) so a new
administrative route cannot silently ship without a check; deny by default;
and add negative tests that assert non-privileged callers are rejected.

## Validation and Regression-Test Results

- `tests/test_vulnerable_security.py::TestVulnerableBrokenFunctionLevelAuth`
  documents the vulnerable behavior: an ordinary user receives `200` and
  the full list (containing the seeded `alice`/`bob`/`admin`), an admin
  also receives `200`, missing/invalid tokens receive `401`, and no
  returned record contains `password_hash`.
- `tests/test_secure_security.py::TestSecureFunctionLevelAuthProtection`
  verifies the fix: an ordinary user receives `403`, an admin receives
  `200` with the full list, missing/invalid tokens receive `401`, and no
  returned record contains `password_hash`.
- Full suite result at the time of writing: **49 passed** (see the README).

## Evidence

The following are rendered terminal-style images generated from the actual
output of `exploits/exploit_bfla.py` against the local apps (they are
rendered captures of real output, not native screenshots):

- `evidence/18-bfla-vulnerable.png` — the exploit against the vulnerable app
  (`:8000`): Alice (an ordinary user) calls `GET /admin/users` and receives
  `200` with all three accounts (`['alice', 'bob', 'admin']`).
- `evidence/19-bfla-secure.png` — the same ordinary-user request against the
  secure app (`:8001`): the response is `403 Admin access required`.

## Evidence Limitations

The evidence images are rendered terminal-style captures of the exploit's
real stdout, not native screenshots, and they show only the status codes
and (safe) usernames returned — no tokens beyond a short prefix and no
password hashes. Reproduce locally with the two commands in the README to
confirm.

## Interview Takeaway

- The three levels of API authorization and how this project now covers all
  three: **object-level** (BOLA — accessing another user's record),
  **property-level** (mass assignment — setting a field you shouldn't), and
  **function-level** (BFLA — invoking an operation you shouldn't).
- Why authentication is not authorization: a valid token proves *who* you
  are, never *what you may do*; each privileged endpoint must decide.
- Why a centralized, deny-by-default authorization dependency is safer than
  repeating per-endpoint checks: it prevents a new admin route from
  shipping without a guard, which is exactly how this flaw arises.
