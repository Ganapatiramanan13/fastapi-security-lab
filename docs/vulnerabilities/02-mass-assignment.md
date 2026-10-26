# Mass Assignment

## Overview

`vulnerable_app`'s `PUT /users/{user_id}` endpoint correctly enforces
*ownership* (a user may only update their own profile), but it applies
every field present in the request body directly to the database row
with no restriction on which fields are allowed. Because the request
schema includes `role` as an ordinary, client-writable field, a normal
authenticated user can include `"role": "admin"` in what looks like an
innocent profile update and grant themselves administrator privileges
in a single request.

## Affected Endpoint

- **Method:** `PUT`
- **Endpoint:** `/users/{user_id}`
- **Application affected:** `vulnerable_app` (fixed in `secure_app`)

## Vulnerable Behavior

`vulnerable_app/schemas.py` defines `UserUpdate` with `role` as a normal
optional field, alongside `username` and `email`:

```python
class UserUpdate(BaseModel):
    username: str | None = None
    email: str | None = None
    role: str | None = None
```

`vulnerable_app/routers/users.py` then applies every field the client
sent, with no allowlist:

```python
if current_user.id != user_id:
    raise HTTPException(status_code=403, detail="You can only update your own profile")

update_data = update.model_dump(exclude_unset=True)
for field, value in update_data.items():
    setattr(user, field, value)   # includes "role" if the client sent it
```

The ownership check is correct — Alice can only ever target her own
`user_id`. The flaw is entirely in *which fields* are allowed to be
set: `role` is a privileged, security-relevant attribute that should
never be client-controlled, but nothing here distinguishes it from a
harmless field like `email`.

## Exploitation

`exploits/exploit_mass_assignment.py` demonstrates the flaw using
Alice's own, legitimately-issued token — no JWT forgery is involved:

1. Logs in as Alice with real credentials via `POST /login`.
2. `GET /users/1` confirms Alice's role is `"user"` before the attack.
3. Sends `PUT /users/1` with her own valid token and body
   `{"email": "alice_new@example.com", "role": "admin"}` — an update to
   her own record, which the ownership check correctly permits.
4. `GET /users/1` again confirms her role is now `"admin"`.
5. Prints a `RESULT: VULNERABLE` line once it confirms the role
   transitioned from `"user"` to `"admin"`.

This exact escalation is also pinned by
`tests/test_vulnerable_security.py::TestVulnerableMassAssignment::test_alice_can_self_promote_to_admin`,
which asserts the role is `"user"` beforehand, `"admin"` in the `PUT`
response, and still `"admin"` on a follow-up `GET` — documenting the
vulnerable behavior deliberately.

This is a local lab demonstration only, run against
`http://127.0.0.1:8000` with locally seeded demo accounts.

## Impact

In a real API, exposing a privileged field like `role` (or similarly
sensitive fields such as an account balance, a subscription tier, or an
`is_verified` flag) through a client-facing update endpoint allows any
authenticated user to escalate their own privileges or manipulate
business-critical state with a single crafted request — no additional
exploit chain required. This is especially dangerous because the
request otherwise looks completely legitimate (a normal user updating
their own profile), making it easy to miss in casual code review or
basic testing that only checks "can Alice edit Alice's own data?"
without checking *which* fields she can edit.

## OWASP Mapping

**OWASP API Security Top 10 (2023 edition) — API3:2023: Broken Object
Property Level Authorization.** The vulnerability is mass assignment of
a sensitive property: the API accepts a client-supplied value for
`role`, a property that should be system-controlled, not
client-writable.

Alice's ownership check is correct — she is authorized to update her
own profile (`current_user.id == user_id`) — but the API never
separately authorizes *which properties* on that record she may
change. Alice is authorized to update her own profile; she is not
authorized to promote herself to administrator. The primary failure
here is property-level authorization, not object ownership: the
object-level decision ("can Alice write to user 1 at all?") is
answered correctly, while the property-level decision ("can Alice set
`role` on any record, including her own?") is never made at all.

The secure fix is to restrict which fields are writable using an
allowlist or a dedicated update schema, rather than trying to
enumerate and block individual sensitive fields after the fact — see
Remediation below.

## Evidence

Confirmed via the exploit script and the automated test suite (not a
screenshot or fabricated log):

- Alice logs in and receives a valid, legitimate access token.
- `GET /users/1` before the attack shows `role: "user"`.
- `PUT /users/1` with `{"email": ..., "role": "admin"}`, using Alice's
  own token on her own record, returns HTTP 200 with `role: "admin"` in
  the response.
- A follow-up `GET /users/1` confirms the change persisted.

This is confirmed by both `exploits/exploit_mass_assignment.py`'s
printed output and the passing assertions in
`test_alice_can_self_promote_to_admin`. No full tokens or secrets are
included in this document.
### Supporting Screenshots

- `evidence/09-mass-assignment-burp-vulnerable.png` — vulnerable request changes the user's role.
- `evidence/10-mass-assignment-burp-privilege-escalation.png` — demonstrates the resulting privilege escalation.
- `evidence/11-mass-assignment-burp-secure.png` — secure application rejects the unauthorized field.
- `evidence/12-mass-assignment-secure-role-unchanged.png` — verifies the user's role remains unchanged.
## Remediation

`secure_app` fixes this with two independent, deliberately redundant
layers of defense.

**1. Schema-level allowlist** (`secure_app/schemas.py`):

```python
class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str | None = Field(default=None, min_length=1)
    email: str | None = None
```

`role` does not exist on this schema at all, and `extra="forbid"` means
any unrecognized field in the request body — including `role` — causes
Pydantic to reject the entire request with `422 Unprocessable Entity`
before the endpoint function ever runs.

`username` is optional: `None` (or an omitted field) means "no username
change was requested". When it *is* provided, `min_length=1` requires it
to be non-empty, so an empty `""` username is rejected with
`422 Unprocessable Entity` at the validation boundary. (This schema does
not constrain whitespace-only values or validate email format.)

**2. Explicit field assignment** (`secure_app/routers/users.py`), as
defense in depth even though the schema already blocks `role`:

```python
if update.username is not None:
    user.username = update.username
if update.email is not None:
    user.email = update.email
```

No generic `setattr` loop over arbitrary request keys is used — only
the two explicitly named, known-safe fields are ever assigned. Ownership
is still enforced exactly as before (`current_user.id == user_id`).

**Duplicate-value handling at commit** (`secure_app/routers/users.py`):
`username` and `email` are unique columns, so a profile update that
collides with another user's value raises a SQLAlchemy `IntegrityError`
on `db.commit()`. The endpoint catches that error, rolls back the
session (`db.rollback()`) so it stays usable, and returns
`409 Conflict` with the generic message `Username or email already in
use`. The response deliberately does not reveal which field collided or
expose any SQL or database internals. (This is a robustness/error-handling
improvement to the secure endpoint; it is not itself the mass-assignment
fix, which is the schema allowlist plus explicit assignment above.)

**Related fix:** while reviewing JWT handling for this project, a
related robustness issue was found and fixed in both apps' `auth.py`:
`get_current_user()` previously converted the JWT's `sub` claim with
`int()` outside the exception-handling block, so a non-numeric `sub`
raised an unhandled `ValueError` and produced a raw `500` instead of a
clean `401`. This is unrelated to mass assignment specifically, but
affects the same authentication dependency both endpoints rely on.

## Secure Verification

`tests/test_secure_security.py::TestSecureMassAssignmentProtection`
verifies the fix directly:

- `test_alice_can_update_her_own_email` — confirms Alice can still
  update her own `email` normally, and that her `role` remains `"user"`
  afterward.
- `test_role_field_is_rejected_by_schema` — confirms a request
  containing `role` is rejected with `422`.
- `test_alice_role_remains_user_after_attempted_escalation` — confirms
  that after attempting the same escalation payload used in the
  exploit, `GET /users/1` still shows `role: "user"`.

## Vulnerable vs Secure

| Aspect | Vulnerable App | Secure App |
|---|---|---|
| Update schema | `role` is a normal, optional, client-writable field | `role` does not exist on the schema; `extra="forbid"` rejects unknown fields |
| Field application | Generic loop: `setattr(user, field, value)` for every field sent | Explicit assignment of only `username`/`email` |
| `PUT` with `{"email": ..., "role": "admin"}` | `200`, role becomes `"admin"` | `422 Unprocessable Entity`, role unchanged |
| Empty `username` (`""`) | Accepted (no length constraint) | `422 Unprocessable Entity` (`min_length=1`) |
| Duplicate `username`/`email` on commit | — | `409 Conflict`, session rolled back, generic message |
| Ownership check | Enforced (`current_user.id == user_id`) | Enforced (`current_user.id == user_id`) |

## Interview Takeaway

- Why mass assignment happens: a request schema mirrors a database
  model too closely, exposing internal/privileged fields as if they
  were ordinary client input.
- The distinction between *ownership* authorization ("can Alice edit
  this record?") and *property-level* authorization ("which fields on
  that record can Alice actually set?") — this vulnerability shows the
  first can be correct while the second is completely missing.
- Why an explicit allowlist is safer than a denylist: a denylist has to
  anticipate every dangerous field in advance, while an allowlist is
  safe by default against fields nobody thought of yet.
- Why defense in depth matters here: even with the strict schema in
  place, the endpoint still assigns fields explicitly rather than via a
  generic loop, so a future accidental schema change wouldn't silently
  reopen the vulnerability.
