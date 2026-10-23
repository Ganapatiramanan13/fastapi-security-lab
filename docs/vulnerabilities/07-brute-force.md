# Brute-Force Authentication (Unthrottled Login)

## Overview

`vulnerable_app`'s `POST /login` endpoint applies no throttling of any
kind: an attacker who knows (or guesses) a username can submit an unlimited
number of password guesses, and every failed attempt is simply answered
with `401`. There is no rate limit, no account lockout, no backoff, and no
attempt counter. This is the precondition for an online brute-force or
credential-stuffing attack. `secure_app`'s `POST /login` applies a SlowAPI
rate limit of **5 requests per minute per client IP**, so after five
attempts further requests from that IP are rejected with `429` before the
credentials are even checked.

## Affected Endpoint

- **Method:** `POST`
- **Endpoint:** `/login`
- **Application affected:** `vulnerable_app` (throttled in `secure_app`)

## Preconditions

- Network access to the login endpoint and a known/guessable username.
- The vulnerable app is running and seeded locally
  (`http://127.0.0.1:8000`).

## Vulnerability Description

`vulnerable_app/routers/login.py` verifies credentials and returns `401` on
failure, with nothing limiting how often it may be called:

```python
@router.post("/login", response_model=LoginResponse)
def login(credentials: LoginRequest, db: Session = Depends(get_db)):
    user = authenticate_user(db, credentials.username, credentials.password)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    ...
```

Because each failed attempt is independent and unthrottled, an attacker can
iterate through a password list at the full speed the server allows. The
generic `401` message ("Invalid username or password") is correct — it does
not disclose whether the username exists — but confidentiality of the
*message* does not help when the *rate* of guessing is unbounded.

## Reproduction Steps

With the vulnerable app seeded and running on `127.0.0.1:8000`:

1. Choose a known username (e.g. `alice`).
2. Submit repeated `POST /login` requests with that username and different
   wrong passwords.

`exploits/exploit_brute_force.py` performs a small, fixed, bounded burst of
8 wrong-password attempts (localhost-only, no flooding) and reports the
status of each. The unbounded behavior is pinned by
`tests/test_vulnerable_security.py::TestVulnerableBruteForce`, which sends
15 wrong-password attempts (all `401`, none `429`) and then confirms the
correct password still works (no lockout).

## Vulnerable vs Secure HTTP Responses

| Request (8 wrong-password attempts for `alice`) | Vulnerable (`:8000`) | Secure (`:8001`) |
|---|---|---|
| Attempts 1–5 | `401` each | `401` each |
| Attempts 6–8 | `401` each (unthrottled) | `429` each (rate limited) |
| Correct password afterwards | `200` (no lockout) | `200` once the window allows |

Observed exploit summary: vulnerable `8 x 401, 0 x 429`; secure
`5 x 401, 3 x 429`.

## Security Impact

Without throttling, an online password-guessing attack is limited only by
network and server throughput, making weak or reused passwords practically
discoverable and enabling large-scale credential stuffing. Combined with any
other weakness (for example a leaked password list), an unthrottled login is
often the most direct path to account takeover. Rate limiting raises the
cost of such attacks from "run a list" to "defeat the throttle," which for a
single client IP is a meaningful barrier.

## Severity Assessment

**Severity: High.** Rationale: the weakness is trivially exploitable
(repeated requests to a public endpoint), it directly enables account
takeover against weak/reused passwords at scale, and it requires no special
privileges. It is not rated Critical in isolation because success still
depends on the target password's strength and on the absence of other
factors (e.g. MFA), and because the secure counterpart demonstrates a
practical mitigation. No CVSS score is asserted; the rating reflects the
lab's isolated behavior.

## OWASP API Security Top 10 and CWE Mapping

- **OWASP API Security Top 10 — API2:2023: Broken Authentication.** The
  authentication endpoint does not protect against automated, high-volume
  credential-guessing.
- **CWE-307: Improper Restriction of Excessive Authentication Attempts** —
  the primary mapping: no limit on repeated failed authentication attempts.
- Related: **CWE-799: Improper Control of Interaction Frequency**.

## Secure Implementation and Remediation

`secure_app/routers/login.py` applies a per-IP rate limit:

```python
@router.post("/login", response_model=LoginResponse)
@limiter.limit("5/minute")
def login(request: Request, credentials: LoginRequest, db=...):
    ...
```

The limiter (`secure_app/limiter.py`) is keyed on the client IP
(`get_remote_address`). After five requests per minute from an IP, the
sixth and later return `429` before the credentials are checked.

### IP-based rate limiting vs account-based lockout

These are different controls and defend against different attacks:

- **IP-based rate limiting** (implemented here) caps how often a single
  *client address* may call the endpoint. It is simple and protects against
  a single-source brute force, but it does **not** stop a *distributed*
  attack spread across many IPs (a botnet or proxy pool), and it can
  over-penalize users who legitimately share an IP (NAT, corporate
  gateways).
- **Account-based lockout** caps failed attempts *per account* regardless of
  source IP, which does blunt distributed guessing against one account — but
  it introduces its own denial-of-service risk, since an attacker can
  deliberately lock a victim out by submitting bad passwords for their
  account.

A production system typically layers several controls: rate limiting,
per-account failure tracking with exponential backoff, CAPTCHA or proof-of-
work on suspicious activity, credential-stuffing detection, and ultimately
multi-factor authentication. This lab implements IP-based rate limiting as
the secure baseline; account lockout is intentionally out of scope for this
stage and is noted as a further hardening step.

### Client-IP trust caveat

IP-based limiting is only as trustworthy as the client IP the application
sees. Behind a reverse proxy or load balancer, `get_remote_address` must be
configured to read the real client IP from a trusted forwarding header
(e.g. `X-Forwarded-For`) set by infrastructure you control; otherwise an
attacker can spoof the header or every request appears to come from the
proxy, defeating or distorting the limit. In this local lab there is no
proxy, so the client IP is the loopback address directly.

## Validation and Regression-Test Results

- `tests/test_vulnerable_security.py::TestVulnerableBruteForce` documents
  the vulnerable behavior: 15 wrong-password attempts all return `401` with
  no `429`, the correct password then succeeds (no lockout), and an unknown
  username returns the same generic `401` (no account-existence disclosure).
- `tests/test_secure_security.py::TestSecureBruteForceProtection` (and the
  existing `TestLoginRateLimit`) verify the control: five failed attempts
  are processed with `401` and the sixth is rejected with `429`. The autouse
  fixture resets the limiter before each test, so the result is deterministic
  and not timing-dependent.
- Full suite result at the time of writing: **63 passed** (see the README).

## Evidence

The following are rendered terminal-style images generated from the actual
output of `exploits/exploit_brute_force.py` against the local apps (they are
rendered captures of real output, not native terminal screenshots):

- `evidence/22-brute-force-vulnerable.png` — the exploit against the
  vulnerable app (`:8000`): all 8 attempts return `401` (`8 x 401, 0 x 429`)
  — unthrottled.
- `evidence/23-brute-force-secure.png` — the same burst against the secure
  app (`:8001`): the first 5 return `401` and attempts 6–8 return `429`
  (`5 x 401, 3 x 429`) — throttled.

## Evidence Limitations

The images are rendered terminal-style captures of the exploit's real
stdout, not native terminal screenshots. They show only HTTP status codes
and a summary; no passwords (the attempted password is deliberately wrong
and is never printed), no tokens, and no secrets appear. The demonstration
uses a small, fixed burst against the loopback interface and is not a load
test. Rate-limit *window reset* over time is not shown here (it would
require waiting out the limiter window) and is not asserted in the tests to
avoid timing-dependent flakiness.

## Interview Takeaway

- Why a correct, non-disclosing `401` is still insufficient: message hygiene
  prevents user enumeration but does nothing about guessing *rate* — the two
  are independent controls.
- The difference between IP-based rate limiting and account lockout, and why
  each has a blind spot (distributed attacks vs lockout-induced DoS).
- Why client-IP trust and proxy configuration matter: an IP-based control is
  only as good as the IP the app can trust, which depends on correct
  forwarded-header handling.
- Why rate limiting is a necessary-but-not-sufficient control, best layered
  with backoff, anomaly detection, and MFA.
