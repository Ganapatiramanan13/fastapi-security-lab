# Account Lockout and Authentication Hardening

## Overview

Stage 5 showed that `vulnerable_app`'s `POST /login` is unthrottled
(unlimited password guessing) and that `secure_app` applies a per-IP rate
limit of 5 requests/minute. This stage adds a second, complementary control
to `secure_app`: a **per-account temporary lockout**. After **5 consecutive
failed-password attempts** on an existing account, that account is locked
for **15 minutes**; while locked, authentication fails even for the correct
password. `vulnerable_app` is unchanged and has no lockout, so after any
number of failures its correct password still logs in.

This is defense-in-depth for the Broken Authentication weakness
(OWASP API2:2023 / CWE-307): IP rate limiting and account lockout defend
against *different* attacker models, and layering them is stronger than
either alone.

## Affected Endpoint

- **Method:** `POST`
- **Endpoint:** `/login`
- **Application affected:** control added to `secure_app`; `vulnerable_app`
  deliberately has no lockout (the demonstration contrast).

## IP-based rate limiting vs account-based lockout

These are distinct controls with different blind spots:

| | Per-IP rate limit (Stage 5) | Per-account lockout (this stage) |
|---|---|---|
| Keyed on | Client IP address | User account |
| Stops | Fast guessing from **one IP** | Guessing against **one account** from **many IPs** |
| Blind spot | **Distributed** attack (botnet / proxy pool) spreads load across IPs | A shared IP can lock out unrelated users' *rate*, but not their accounts |
| Window | 1 minute (short) | 15 minutes (longer) |
| Its own risk | Over-penalizes shared/NAT IPs | **Targeted lockout DoS** (see below) |

The lab keeps **both**. The rate limit caps how *often* one IP may call
`/login`; the lockout caps how many times one *account* may fail before it
is temporarily frozen, regardless of source IP.

## Precedence / interaction (verified)

SlowAPI's `@limiter.limit("5/minute")` runs as a decorator **before** the
endpoint body, so within a one-minute window the **6th+ request from one IP
returns `429` before the lockout logic executes**. Requests 1–5 run the
endpoint and increment the account's failure counter; the 5th consecutive
failure sets the lock. Therefore, from a single IP, the rate limit is what
an attacker hits first; the account lockout becomes decisive when attempts
are **spread over time** (the 1-minute IP window resets, but the failure
counter persists until a success or the 15-minute lock expires) or come from
**many IPs** against one account. The regression tests observe the lock in
isolation by resetting the in-memory limiter between the failures and the
final attempt.

## Root Cause (vulnerable app) and Fix (secure app)

Root cause: `vulnerable_app` counts nothing and locks nothing, so repeated
failures have no cumulative consequence. Fix: `secure_app/auth.py`'s
`authenticate_user_with_lockout()` tracks `failed_login_attempts` and
`locked_until` on the user row:

```python
LOCKOUT_MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

# (within authenticate_user_with_lockout)
if user.locked_until and user.locked_until <= now:      # expired -> clear
    user.locked_until = None; user.failed_login_attempts = 0; db.commit()
if user.locked_until and user.locked_until > now:       # active lock
    return None                                         # fail WITHOUT checking pw
if not verify_password(password, user.password_hash):   # wrong pw
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= LOCKOUT_MAX_ATTEMPTS:
        user.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
    db.commit(); return None
# success -> reset counter + clear lock
```

- The lock is checked **before** password verification, so a locked account
  is refused even with the correct password.
- A **successful** authentication resets the counter and clears the lock.
- An **expired** lock is cleared on the next attempt, and authentication
  proceeds normally.

## Anti-enumeration (generic 401)

A locked account returns the **same generic `401 "Invalid username or
password"`** used for a wrong password and for an unknown username. No
distinct `423 Locked` is returned, because a status that only appears for
*existing, locked* accounts would disclose which usernames exist (account
enumeration). The trade-off is that a legitimate user is not told *why* they
cannot log in; in a real system that is typically handled out-of-band
(email notification, account-recovery flow) rather than by a distinguishing
response.

## Unknown usernames

Lockout state is stored on the user row, so **nonexistent usernames create
no state** (there is no row to lock, and inventing one would be an
unbounded-write / enumeration vector). Repeated attempts against an unknown
username return the same generic `401`, and the per-IP rate limit still
applies to such spraying.

## Denial-of-Service trade-off (must be understood)

Account lockout introduces a **targeted DoS**: an attacker who knows a
victim's username can submit 5 wrong passwords and lock that victim out for
15 minutes, repeatedly. This is inherent to hard per-account lockout.
Practical alternatives / mitigations (not implemented in this lab, noted for
completeness):

- **Progressive delays / exponential backoff** instead of a hard lock, which
  slows attackers without fully denying the legitimate user.
- **IP- or device-scoped** failure tracking so one attacker cannot lock a
  victim from an unrelated network.
- **CAPTCHA / proof-of-work** after a few failures.
- **Self-service unlock** via a verified second factor or email link.
- **Multi-factor authentication**, which makes online password guessing far
  less valuable regardless of lockout.

This lab implements the simplest temporary per-account lock to demonstrate
the control and its trade-off clearly.

## Concurrency / atomicity limitation (honest scope)

The counter update is a read-modify-write within a single request's
SQLAlchemy session and is committed per attempt. It is **not atomic across
truly concurrent requests** on SQLite: two simultaneous failed attempts
could interleave and under-count by one. For this single-process
educational lab (and its in-process test client) that is acceptable and
does not affect the demonstration. A production implementation would use an
atomic `UPDATE ... SET attempts = attempts + 1`, a row-level lock, or a
dedicated attempt store (e.g. Redis with atomic operations). This is stated
rather than claimed to be production-grade.

## Database migration note

The two new columns (`failed_login_attempts`, `locked_until`) are picked up
automatically here because the lab recreates tables from the models on
startup and reseeds them in tests (`Base.metadata.create_all` /
`drop_all`). **A real deployment with a persistent database would require a
schema migration** (e.g. Alembic) to add these columns without data loss;
table recreation is a lab convenience, not a substitute for migrations.

## Severity / classification

This stage adds a **security control / hardening**, not a new vulnerability.
The underlying weakness it strengthens — unthrottled authentication — is
**OWASP API2:2023 Broken Authentication / CWE-307 (Improper Restriction of
Excessive Authentication Attempts)**, already demonstrated in report 07. The
vulnerable app's lack of lockout (correct password still works after many
failures) remains the High-severity demonstration; the secure app shows the
layered mitigation.

## Validation and Regression-Test Results

`tests/test_secure_security.py::TestSecureAccountLockout` verifies,
deterministically and without any `sleep`:

1. The fixture reseed starts each account unlocked (state isolation).
2. Four failures then a correct login succeeds (below threshold).
3. The account is locked after the fifth consecutive failure (DB state).
4. A correct password is refused with a generic `401` while locked.
5. Login succeeds after the lock expires — expiry is forced by writing a
   past `locked_until` directly to the DB (no wall-clock wait) — and the
   state resets.
6. A successful authentication resets the failure counter.
7. Locking Alice does not lock Bob (per-account isolation).
8. An unknown username returns the generic `401` and creates no row/state.
9. The existing per-IP limit still returns `5×401` then `429`.
10. Precedence: the IP limit answers the 6th request (`429`) before the
    endpoint; after clearing the limiter, the account lock yields `401`.

Expiry is tested with a controlled DB timestamp rather than a timer, so the
tests are deterministic and never leave an account locked for later tests
(the autouse reseed also resets `failed_login_attempts`/`locked_until`).

Full suite result at the time of writing: **73 passed** (see the README).

## Evidence

The following are rendered terminal-style images generated from the actual
output of `exploits/exploit_account_lockout.py` against the local apps (they
are rendered captures of real output, not native terminal screenshots):

- `evidence/24-account-lockout-vulnerable.png` — the demo against the
  vulnerable app (`:8000`): after 5 failed attempts the correct password is
  still accepted (`HTTP 200`) — no lockout.
- `evidence/25-account-lockout-secure.png` — the demo against the secure app
  (`:8001`): after 5 failed attempts and once the per-IP window clears, the
  correct password is refused (`HTTP 401`) — the account is locked.

## Evidence Limitations

The demo waits ~62 seconds (one per-IP rate-limit window) so that the final
request reaches the endpoint and the account lock — not the 60-second IP
limit — is what the `401` reflects. It sends only 6 requests total (5 wrong
+ 1 correct), loopback-only, http/https only, and prints no passwords,
tokens, or secrets. The images are rendered terminal-style captures, not
native screenshots. The lock-expiry path is exercised by the regression
tests (via a controlled DB timestamp), not by the demo.

## Interview Takeaway

- Why layering IP rate limiting and account lockout matters: they stop
  different attacks (single-IP speed vs single-account distributed guessing).
- Why a locked account should return a generic error: a distinguishing
  status reintroduces account enumeration.
- The targeted-lockout DoS and why progressive backoff / MFA are often
  preferred to a hard lock in production.
- Why atomic counter updates and real migrations matter once you leave the
  single-process lab.
