# Unrestricted Resource Consumption (Admin Users Listing)

## Overview

`vulnerable_app`'s `GET /admin/users` endpoint returns the entire `users`
table in a single response with no pagination and no page-size cap
(`db.query(User).all()`). A client cannot limit the response and the server
imposes no bound, so the response size grows without limit as the table
grows. The endpoint also ignores any client-supplied `limit`, confirming
there is no bound at all. This is Unrestricted Resource Consumption: the
work and memory the server spends on a single request are controlled by the
dataset size rather than by an enforced limit.

This is distinct from the project's existing authorization findings — it is
not about *who* may call the endpoint but about the *unbounded size* of the
work the endpoint performs.

## Affected Endpoint

- **Method:** `GET`
- **Endpoint:** `/admin/users`
- **Application affected:** `vulnerable_app` (bounded in `secure_app`)

## Preconditions

- A caller able to reach the endpoint. (On the vulnerable app any
  authenticated user can, due to the separate BFLA finding; this
  demonstration uses the admin account so the comparison is strictly about
  result-set bounds, not authorization.)
- The vulnerable app is running and seeded locally
  (`http://127.0.0.1:8000`).

## Vulnerability Description

`vulnerable_app/routers/admin.py`:

```python
@router.get("/admin/users", response_model=list[UserOut])
def list_users(current_user=..., db=...):
    return db.query(User).all()   # no limit, no offset, no cap
```

There is no `limit`/`offset` parameter and no server-side maximum, so:

- the full table is always returned, and
- a client-supplied `?limit=N` is ignored (there is no such parameter).

As the `users` table grows (or on any endpoint that returns a large,
client-influenced collection), a single request forces the server to load,
serialize, and transmit the whole set — wasting CPU, memory, and bandwidth,
and enabling a cheap denial-of-service or data-exfiltration-at-scale
primitive.

## Reproduction Steps

With the vulnerable app seeded and running on `127.0.0.1:8000`:

1. Log in as admin (`admin` / `admin_password123`) via `POST /login`.
2. Send `GET /admin/users?limit=100000` — accepted with `200` (the
   oversized request is not rejected).
3. Send `GET /admin/users?limit=1` — still returns the full list (the
   `limit` is ignored).

`exploits/exploit_unrestricted_resource_consumption.py` performs exactly
these steps (localhost-only, GET-only, no flooding). The unbounded behavior
is pinned at scale by
`tests/test_vulnerable_security.py::TestVulnerableResourceConsumption`,
which inserts 150 extra users and asserts all 153 are returned in one
response and that `?limit=1` is ignored.

## Vulnerable vs Secure HTTP Responses

| Request (as admin) | Vulnerable (`:8000`) | Secure (`:8001`) |
|---|---|---|
| `GET /admin/users` | `200`, entire table | `200`, first 20 (default page) |
| `GET /admin/users?limit=1` | `200`, entire table (ignored) | `200`, exactly 1 row |
| `GET /admin/users?limit=100000` | `200`, entire table (accepted) | `422` (exceeds max 100) |
| `GET /admin/users?limit=0` | `200`, entire table (ignored) | `422` (below min 1) |
| `GET /admin/users?offset=-1` | `200`, entire table (ignored) | `422` (offset must be >= 0) |

## Security Impact

Unbounded list endpoints let a single cheap request consume
disproportionate server resources (CPU, memory, bandwidth), which can
degrade or deny service as data volume grows — and let an authorized-but-
over-broad caller exfiltrate an entire table in one call rather than in
rate-limitable pages. In real APIs this is a common and high-impact issue
because the endpoint looks ordinary and behaves fine with small test data,
only becoming dangerous at production scale.

## Severity Assessment

**Severity: Medium.** Rationale: no authentication or authorization bypass
is involved and no new data is exposed beyond what the endpoint already
returns; the risk is resource exhaustion / denial of service and
bulk-retrieval that scales with table size. It is not Low because the flaw
is trivially triggerable and worsens precisely as the system grows, and not
High because, in isolation, it does not grant unauthorized access or
corrupt data. No CVSS score is asserted; the rating reflects the lab's
isolated behavior.

## OWASP API Security Top 10 Mapping

**OWASP API Security Top 10 — API4:2023: Unrestricted Resource
Consumption.** The API does not limit the size of a response a client can
request, allowing a single request to consume resources proportional to the
whole dataset. This is a resource-consumption issue, not an authorization
one, so it is deliberately not mapped to API1/API3/API5.

## CWE Mapping

- **CWE-770: Allocation of Resources Without Limits or Throttling** — the
  endpoint returns an unbounded result set with no page-size limit.
- Related: **CWE-400: Uncontrolled Resource Consumption**.

## Secure Implementation and Remediation

`secure_app/routers/admin.py` bounds the result set with validated
pagination parameters:

```python
@router.get("/admin/users", response_model=list[UserOut])
def list_users(
    current_user=..., db=...,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return db.query(User).order_by(User.id).offset(offset).limit(limit).all()
```

- `limit` is validated to **1..100** with a default of **20**; `offset`
  must be **>= 0**. FastAPI/Pydantic rejects out-of-range values with a
  normal `422` before the handler runs, so a client can never request an
  unbounded or arbitrarily large page.
- The query is explicitly ordered by `id`, so pagination is deterministic
  (no duplicated or skipped rows across pages).
- The existing admin-role check (BFLA fix) and the safe `UserOut` schema
  (never exposing `password_hash`) are preserved — pagination does not
  weaken authentication or authorization.

**Prevention (general):** apply a default and a maximum page size to every
collection endpoint; validate pagination inputs; order results
deterministically; and consider complementary controls (overall request
rate limits, response size/time budgets) for resource-consumption defense
in depth.

## Validation and Regression-Test Results

- `tests/test_vulnerable_security.py::TestVulnerableResourceConsumption`
  documents the vulnerable behavior with 150 inserted users: the endpoint
  returns all 153 accounts in one response and ignores `?limit=1`.
- `tests/test_secure_security.py::TestSecureResourceConsumption` verifies
  the fix: the default page size caps results at 20; `limit`/`offset`
  paginate deterministically over disjoint windows; `limit=0`, `limit=101`,
  and `offset=-1` each return `422`; the admin role is still required
  (`403` for a non-admin); missing/invalid tokens return `401`; and no
  returned record contains `password_hash`.
- The extra users are inserted directly into each app's isolated test
  database with a dummy (non-bcrypt) `password_hash` and are removed by the
  existing autouse reseed fixture before the next test, keeping tests fast,
  deterministic, and isolated. No denial-of-service load test is performed.
- Full suite result at the time of writing: **60 passed** (see the README).

## Evidence

The following are rendered terminal-style images generated from the actual
output of `exploits/exploit_unrestricted_resource_consumption.py` against
the local apps (they are rendered captures of real output, not native
screenshots):

- `evidence/20-resource-consumption-vulnerable.png` — the exploit against
  the vulnerable app (`:8000`): `?limit=100000` is accepted with `200` and
  `?limit=1` still returns the full list, demonstrating no page-size bound.
- `evidence/21-resource-consumption-secure.png` — the same requests against
  the secure app (`:8001`): `?limit=100000` is rejected with `422` and
  `?limit=1` returns exactly one row.

## Evidence Limitations

The live exploit runs against the seeded three-user database, so the row
counts in the images are small (the vulnerable app returns 3 for both an
oversized and a tiny `limit`, which is exactly the point — the `limit` is
ignored and no bound is applied). The *scale* of the unbounded behavior
(all 153 of 153 users returned in one response) is demonstrated by the
automated regression test rather than by flooding a running server. The
images are rendered terminal-style captures, not native screenshots, and
contain no tokens beyond a short prefix and no password hashes.

## Interview Takeaway

- Why "it works in testing" hides this class of bug: an unbounded list is
  harmless with three rows and dangerous with three million; the defect is
  the *absence of a limit*, not the current response size.
- Why a maximum page size (not just a default) matters: a default protects
  the naive client, but only an enforced maximum stops a malicious client
  from requesting everything at once.
- Why deterministic ordering is part of correct pagination: without an
  explicit `ORDER BY`, `offset`/`limit` can skip or duplicate rows across
  pages.
- How this complements rate limiting: rate limiting bounds how *often* a
  client calls; pagination bounds how *much* each call can consume.
