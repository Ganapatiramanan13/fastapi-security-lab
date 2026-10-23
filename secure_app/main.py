
"""
Entry point for the SECURE FastAPI app.

Hardened routers are added here to match the vulnerable app's endpoints.
"""

import math
import os

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from secure_app.limiter import limiter

from secure_app.database import Base, engine
from secure_app.routers import admin, login, orders, users

# Create the rate limiter once and share it with the login router.



# Create all database tables if they do not already exist.
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Secure FastAPI Security Lab",
    description="Hardened counterpart to the vulnerable app, used for comparison.",
)

# FIX (Security Misconfiguration, OWASP API8:2023) — CORS allowlist.
# Never a wildcard: only these explicit origins may make cross-origin
# requests, and the list is configurable via SECURE_APP_ALLOWED_ORIGINS
# (comma-separated). A disallowed Origin receives no
# Access-Control-Allow-Origin header (so a browser blocks the cross-origin
# read), and a disallowed preflight is rejected with 400.
def _parse_allowed_origins(raw: str) -> list[str]:
    """
    Parse the CORS allowlist from a comma-separated string.

    Trims whitespace and drops empty entries (an empty allowlist is
    valid and fails closed: no origin is allowed). REFUSES a wildcard:
    an explicit "*" raises RuntimeError at startup, so the secure app
    can never silently run with wildcard CORS (which, combined with
    allow_credentials, would reflect any origin).
    """
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    if "*" in origins:
        raise RuntimeError(
            "SECURE_APP_ALLOWED_ORIGINS must not contain '*'. Wildcard "
            "CORS is refused by the secure app; list explicit origins "
            "instead."
        )
    return origins


_ALLOWED_ORIGINS = _parse_allowed_origins(
    os.environ.get(
        "SECURE_APP_ALLOWED_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    )
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    """
    FIX (Security Misconfiguration, OWASP API8:2023) — set security
    response headers on every response (including error and rate-limit
    responses, because this middleware wraps the whole app).

    - X-Content-Type-Options: nosniff — stop MIME-type sniffing.
    - X-Frame-Options: DENY and CSP frame-ancestors 'none' —
      anti-clickjacking. X-Frame-Options is the legacy control;
      Content-Security-Policy frame-ancestors is the modern, more
      expressive one. Both are sent for broad coverage.
    - Referrer-Policy: no-referrer — do not leak URLs to other origins.
    - Strict-Transport-Security is sent but ONLY takes effect over HTTPS;
      browsers ignore it over plain HTTP. It assumes TLS terminated at a
      proxy in a real deployment and provides NO protection for this
      local HTTP lab — it documents intent, not an active control here.
    """
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = (
        "max-age=63072000; includeSubDomains"
    )
    return response


# Configure SlowAPI.
app.state.limiter = limiter
app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler,
)


@app.exception_handler(RequestValidationError)
async def _validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Return a JSON-safe 422 for request-validation errors.

    Pydantic rejects non-finite numbers (NaN / +/-Infinity) because the
    order schema sets allow_inf_nan=False, but it echoes the offending
    value back in the error context. A request body may legitimately
    carry those literals (Python's JSON parser, used by Starlette,
    accepts them), and Starlette renders responses with allow_nan=False
    — so echoing a non-finite float in the 422 body would raise and
    surface as a 500. We stringify any non-finite float anywhere in the
    error payload so the rejection is reported cleanly as a 422.
    """
    def _finite_safe(obj):
        if isinstance(obj, float) and not math.isfinite(obj):
            return str(obj)
        if isinstance(obj, dict):
            return {k: _finite_safe(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_finite_safe(v) for v in obj]
        return obj

    errors = _finite_safe(jsonable_encoder(exc.errors()))
    return JSONResponse(status_code=422, content={"detail": errors})

# Register routers.
app.include_router(login.router)
app.include_router(users.router)
app.include_router(orders.router)
app.include_router(admin.router)


@app.get("/health")
def health_check():
    """Confirm that the application is running."""
    return {"status": "ok"}
