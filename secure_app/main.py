
"""
Entry point for the SECURE FastAPI app.

Hardened routers are added here to match the vulnerable app's endpoints.
"""

from fastapi import FastAPI
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from secure_app.limiter import limiter

from secure_app.database import Base, engine
from secure_app.routers import admin, login, users

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

# Register routers.
app.include_router(login.router)
app.include_router(users.router)
app.include_router(admin.router)


@app.get("/health")
def health_check():
    """Confirm that the application is running."""
    return {"status": "ok"}
