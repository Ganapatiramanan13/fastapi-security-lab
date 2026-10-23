
"""
Entry point for the SECURE FastAPI app.

Hardened routers are added here to match the vulnerable app's endpoints.
"""

import math

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
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
