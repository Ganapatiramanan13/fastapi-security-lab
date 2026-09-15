# BOLA / IDOR (Broken Object Level Authorization)

## Overview

`vulnerable_app`'s `GET /users/{user_id}` endpoint checks that a request
carries a *valid* JWT, but never checks whether the person holding that
JWT actually owns the specific `user_id` being requested. Any logged-in
user can view any other user's record simply by changing the number in
the URL. This is a textbook Broken Object Level Authorization (BOLA) —
also commonly called an Insecure Direct Object Reference (IDOR).

## Affected Endpoint

- **Method:** `GET`
- **Endpoint:** `/users/{user_id}`
- **Application affected:** `vulnerable_app` (fixed in `secure_app`)

## Vulnerable Behavior

`vulnerable_app/routers/users.py` requires authentication via
`get_current_user`, receives the authenticated user as `current_user`,
but never compares `current_user.id` to the `user_id` path parameter
before returning the record:

```python
@router.get("/users/{user_id}", response_model=UserOut)
def get_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user
```

`current_user` is fetched (proving the caller's identity is known to the
handler) but is never used to restrict which `user_id` may be accessed.
Authentication is enforced; authorization is not.

## Exploitation

`exploits/exploit_bola.py` demonstrates the flaw using only a
legitimately-issued token — no JWT forgery is involved in this script:

1. Logs in as Alice with her real credentials (`alice` /
   `alice_password123`) via `POST /login` and obtains a real access
   token.
2. Requests `GET /users/1` (Alice's own record, `user_id=1`) with that
   token — this succeeds, as expected, and is not itself a problem.
3. Reuses the **same** token, unmodified, against `GET /users/2` (Bob's
   record). The vulnerable app returns Bob's data with HTTP 200, even
   though Alice's token proves nothing about any relationship to Bob's
   account.
4. Prints a `RESULT:` line confirming the object was returned when it
   should not have been.

This exact scenario — Alice's token retrieving Bob's data — is also
pinned by an automated test:
`tests/test_vulnerable_security.py::TestVulnerableBOLA::test_alice_token_can_view_bobs_profile_bola`,
which asserts the response is `200` with Bob's `id` and `username` —
documenting the vulnerable behavior deliberately, not accidentally.

This is a local lab demonstration only, run against
`http://127.0.0.1:8000` with locally seeded demo accounts.

## Impact

In a real API, this class of flaw allows any authenticated user —
including a free-tier or low-privilege account — to enumerate and read
every other user's data by iterating over object IDs. Depending on what
the object contains, this can expose personal information, financial
records, private messages, or other users' account details at scale,
with no special tooling beyond changing a number in a URL. It is
consistently one of the most commonly reported API vulnerability
classes in real-world bug bounty and penetration testing findings.

## OWASP Mapping

**OWASP API Security Top 10 — API1:2023: Broken Object Level
Authorization.** The API authenticates the caller correctly but fails
to verify that the caller is authorized to access the *specific object*
identified in the request.

## Evidence

Confirmed via the exploit script and the automated test suite (not a
screenshot or fabricated log):

- Alice logs in and receives a valid, legitimate access token.
- Alice's own request, `GET /users/1`, correctly returns her own data.
- The same token, reused against `GET /users/2`, returns Bob's user
  record (`username: "bob"`, `id: 2`) with HTTP 200 — confirmed by both
  `exploits/exploit_bola.py`'s printed output and the passing assertion
  in `test_alice_token_can_view_bobs_profile_bola`.

No full tokens or secrets are included in this document.

## Remediation

`secure_app/routers/users.py` fixes this by adding an explicit
object-level authorization check before the target user is ever
queried:

```python
is_admin = current_user.role == "admin"
is_self = current_user.id == user_id

if not (is_admin or is_self):
    raise HTTPException(status_code=403, detail="You are not authorized to access this user's data")
```

- A caller may access their **own** record (`current_user.id ==
  user_id`), or any record if they hold the `admin` role.
- Everyone else receives `403 Forbidden`, returned **before** the
  database is queried for the target user — so the check cannot be used
  to distinguish "exists but forbidden" from "doesn't exist" by timing
  or response shape.
- `404 Not Found` is still returned separately, only after the
  authorization check passes, for a genuinely missing user ID.

## Secure Verification

`tests/test_secure_security.py::TestSecureBOLAProtection` verifies the
fix directly:

- `test_alice_can_view_her_own_profile` — confirms `GET /users/1` as
  Alice still returns `200` with her own data.
- `test_alice_cannot_view_bobs_profile` — confirms `GET /users/2` as
  Alice now returns `403`, exactly where the vulnerable app returned
  `200`.

## Vulnerable vs Secure

| Aspect | Vulnerable App | Secure App |
|---|---|---|
| Authentication check | Required (valid JWT) | Required (valid JWT) |
| Authorization check | None — `current_user` fetched but unused | Self-or-admin check enforced before object access |
| Alice → `GET /users/2` (Bob's data) | `200`, Bob's data returned | `403 Forbidden` |
| Alice → `GET /users/1` (her own data) | `200` | `200` |

## Interview Takeaway

- The difference between **authentication** ("who are you") and
  **authorization** ("what are you allowed to do") — this vulnerability
  is a pure authorization failure despite correct authentication.
- Why BOLA/IDOR is fundamentally an *object-level* authorization
  problem: a valid session says nothing about ownership of a specific
  resource ID.
- Why the fix has to happen on the server for every request, not by
  hiding IDs or relying on the client not to guess them ("security
  through obscurity" is not a fix).
- Why returning `403` before querying the object (rather than `404`
  only for missing objects) avoids leaking which IDs exist.
