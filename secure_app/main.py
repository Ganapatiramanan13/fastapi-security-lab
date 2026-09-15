"""
Entry point for the SECURE FastAPI app.

Hardened routers are added here to match the vulnerable app's endpoints
(login, users, profile, orders, admin), with fixes applied one stage at
a time.
"""

from fastapi import FastAPI

from secure_app.database import Base, engine
from secure_app.routers import admin, login, users

# Create all tables (users, orders) if they don't already exist.
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Secure FastAPI Security Lab",
    description="Hardened counterpart to the vulnerable app, used for comparison.",
)

app.include_router(login.router)
app.include_router(users.router)
app.include_router(admin.router)


@app.get("/health")
def health_check():
    """Simple liveness check — confirms the app is running."""
    return {"status": "ok"}
