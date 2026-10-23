# Security Misconfiguration (CORS and Missing Security Headers)

## Overview

`vulnerable_app` is misconfigured for cross-origin access and ships no
security response headers. Its CORS policy is wide open
(`allow_origins=["*"]` **with** `allow_credentials=True`), and it sets none
of the common security headers. `secure_app` restricts CORS to an explicit,
configurable origin allowlist and adds security headers to every response.

This is a configuration flaw, not a code-logic flaw: the endpoints,
authentication, and authorization are identical to before. What differs is
how the application is *configured* to be consumed by browsers.

## Affected Component

- **Scope:** application-level middleware (CORS + response headers).
- **Observed on:** every endpoint; demonstrated on `GET /health`.
- **Application affected:** `vulnerable_app` (fixed/hardened in `secure_app`).

## Verified Starlette/FastAPI behavior (not assumed)

`allow_origins=["*"]` combined with `allow_credentials=True` does **not**
emit a literal `Access-Control-Allow-Origin: *`. Because the CORS spec
forbids `*` together with credentials, Starlette instead **reflects the
caller's `Origin`** back in `Access-Control-Allow-Origin` and adds
`Access-Control-Allow-Credentials: true`. Verified with `TestClient`:

```
VULNERABLE  GET /health, Origin: https://evil.example
  -> Access-Control-Allow-Origin: https://evil.example
     Access-Control-Allow-Credentials: true          (any origin reflected)
```

Reflecting an arbitrary origin while allowing credentials is effectively
"allow all origins, with cookies/Authorization" — the dangerous combination,
reached indirectly rather than via a literal `*`.

## Important testing caveat

`TestClient` (and this stage's demo) report **the headers the server
sends**, not the browser's enforcement. The same-origin policy is enforced
by the *browser*; these tests prove the server is *configured* to permit (or
refuse) the cross-origin read, which is exactly what a browser acts on. A
response merely *containing* CORS headers does not by itself prove a browser
performed a credentialed cross-origin read — but a server that reflects an
arbitrary origin with credentials is precisely the misconfiguration a
browser would honor.

## Vulnerable vs Secure (verified)

| Check (`GET /health`, `Origin: https://evil.example`) | Vulnerable `:8000` | Secure `:8001` |
|---|---|---|
| `Access-Control-Allow-Origin` | `https://evil.example` (reflected) | **absent** |
| `Access-Control-Allow-Credentials` | `true` | `true`* |
| Preflight `OPTIONS` (disallowed origin) | `200`, origin reflected | **`400` "Disallowed CORS origin"** |
| `X-Content-Type-Options` | absent | `nosniff` |
| `X-Frame-Options` | absent | `DENY` |
| `Content-Security-Policy` | absent | `frame-ancestors 'none'` |
| `Referrer-Policy` | absent | `no-referrer` |

\* For a disallowed origin the secure app still emits
`Access-Control-Allow-Credentials: true` but **omits**
`Access-Control-Allow-Origin`. A browser requires `Access-Control-Allow-Origin`
to match the request origin before exposing the response, so with no matching
`ACAO` the cross-origin read is blocked; the lone `ACAC` header is inert
without it. (An allowlisted origin receives a matching `ACAO`.)

## Security Impact

- **Permissive CORS + credentials:** a logged-in victim who visits an
  attacker's page could have their browser issue credentialed requests to
  the API and **read the authenticated responses** cross-origin (data theft,
  CSRF-like read attacks). Reflecting any origin defeats the purpose of CORS.
- **Missing `X-Content-Type-Options`:** browsers may MIME-sniff responses,
  enabling some content-type confusion / XSS vectors.
- **Missing framing policy (`X-Frame-Options` / CSP `frame-ancestors`):**
  the app can be framed by a malicious site for **clickjacking**.
- **Missing `Referrer-Policy`:** full URLs (possibly containing sensitive
  path/query data) may leak to third-party sites via the `Referer` header.

## Severity Assessment

**Severity: Medium (CORS misconfiguration up to High in context).** The
permissive, credentialed CORS is the most serious part — it can expose
authenticated data cross-origin — but its real impact depends on whether the
API uses cookie/credential-based sessions a browser would attach, and on
what a victim is lured into visiting. The missing headers are defense-in-depth
gaps rather than direct data exposure. No CVSS score is asserted; the rating
reflects the lab's isolated behavior.

## OWASP API Security Top 10 and CWE Mapping

- **OWASP API Security Top 10 — API8:2023: Security Misconfiguration.**
  Missing or overly permissive CORS and absent security headers are classic
  examples under this category.
- **CWE-942: Permissive Cross-domain Policy with Untrusted Domains** — the
  CORS policy trusts any origin (reflected) with credentials.
- **CWE-1021: Improper Restriction of Rendered UI Layers or Frames**
  (clickjacking) — no framing policy.
- Related: **CWE-16 (Configuration)** and **CWE-693 (Protection Mechanism
  Failure)** for the missing hardening headers generally.

## Secure Implementation and Remediation

`secure_app/main.py`:

```python
_ALLOWED_ORIGINS = [...]  # from SECURE_APP_ALLOWED_ORIGINS, default localhost dev origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,     # explicit allowlist, NEVER "*"
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

@app.middleware("http")
async def _security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response
```

- **CORS allowlist, never a wildcard.** Only configured origins get a
  matching `Access-Control-Allow-Origin`; others get none, and a disallowed
  preflight is rejected with `400`. The allowlist is configurable via the
  `SECURE_APP_ALLOWED_ORIGINS` environment variable.
- **Framing policy:** `X-Frame-Options: DENY` (legacy browsers) **and** CSP
  `frame-ancestors 'none'` (modern, more expressive) — both documented.
- **`X-Content-Type-Options: nosniff`** and **`Referrer-Policy: no-referrer`**
  round out the baseline hardening.
- The headers are applied by a middleware that wraps the whole app, so they
  appear on **every** response, including `401`, `422`, and `429`
  (verified by tests).

### HSTS caveat (no false protection claimed)

`Strict-Transport-Security` is set, but it **only takes effect over HTTPS** —
browsers ignore it over plain HTTP. This local lab serves plain HTTP, so HSTS
provides **no protection here**; it documents intent and assumes TLS is
terminated by a proxy/load balancer in a real deployment. It is included so
the configuration is complete, not because it does anything over `http://`.

## Validation and Regression-Test Results

- `tests/test_vulnerable_security.py::TestVulnerableSecurityMisconfiguration`
  documents the misconfiguration: an arbitrary `Origin` is reflected with
  `Access-Control-Allow-Credentials: true`, and no security headers are
  present.
- `tests/test_secure_security.py::TestSecureSecurityMisconfiguration` verifies
  the fix: an allowlisted origin is echoed, a disallowed origin is not, a
  disallowed preflight returns `400`, the security headers are present
  (including on a `401` and a `429`), and the existing rate limiter still
  returns `429` after the 5th attempt.
- Each test asserts the server's response headers via `TestClient`, not
  browser enforcement (see the testing caveat above).
- The existing IP rate limiter and per-account lockout continue to function
  with the middleware in place (verified).
- Full suite result at the time of writing: **82 passed** (see the README).

## Evidence

The following are rendered terminal-style images generated from the actual
output of `exploits/exploit_security_misconfiguration.py` against the local
apps (they are rendered captures of real output, not native terminal
screenshots):

- `evidence/26-security-misconfig-vulnerable.png` — the vulnerable app
  (`:8000`) reflects `https://evil.example` in `Access-Control-Allow-Origin`
  with credentials and sends no security headers.
- `evidence/27-security-misconfig-secure.png` — the secure app (`:8001`) does
  not echo the arbitrary origin, rejects the disallowed preflight with `400`,
  and sends the security headers.

## Evidence Limitations

The demo inspects **server response headers** for a request carrying an
`Origin` header; it does not run a browser and does not prove a cross-origin
read succeeds. The `Origin` value (`https://evil.example`) is only ever sent
as a header string — no request is made to that host; the demo contacts only
the loopback target, over http/https, against `/health`. The images are
rendered terminal-style captures, not native screenshots; no passwords,
tokens, or secrets appear.

## Interview Takeaway

- Why `allow_origins=["*"]` + `allow_credentials=True` is dangerous even
  though the server never sends a literal `*`: the framework reflects the
  origin, which is "allow everyone, with credentials."
- CORS is **not** an authentication or authorization control — it governs
  which *browsers'* script contexts may read a response; it does nothing for
  non-browser clients.
- Why security headers are defense-in-depth (nosniff, framing policy,
  referrer policy) and why HSTS is meaningless over plain HTTP.
- The difference between "the server sent CORS headers" and "a browser
  allowed a credentialed cross-origin read" — the server configuration is
  the thing you control and test.
