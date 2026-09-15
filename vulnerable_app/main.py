"""
Entry point for the VULNERABLE FastAPI app.

At this stage the app only exposes a health check endpoint. Vulnerable
routers (login, users, profile, orders, admin) will be added in later
stages, one vulnerability category at a time.
"""

from fastapi import FastAPI

from vulnerable_app.database import Base, engine
from vulnerable_app.routers import admin, login, users

# Create all tables (users, orders) if they don't already exist.
# In a real project you'd use migrations (e.g. Alembic); for this local
# educational lab, creating tables on startup is simple and sufficient.
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Vulnerable FastAPI Security Lab",
    description="Intentionally insecure API used for security education.",
)

app.include_router(login.router)
app.include_router(users.router)
app.include_router(admin.router)


@app.get("/health")
def health_check():
    """Simple liveness check — confirms the app is running."""
    return {"status": "ok"}
