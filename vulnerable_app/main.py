"""
Entry point for the VULNERABLE FastAPI app.

At this stage the app only exposes a health check endpoint. Vulnerable
routers (login, users, profile, orders, admin) will be added in later
stages, one vulnerability category at a time.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from vulnerable_app.database import Base, engine
from vulnerable_app.routers import admin, login, orders, users

# Create all tables (users, orders) if they don't already exist.
# In a real project you'd use migrations (e.g. Alembic); for this local
# educational lab, creating tables on startup is simple and sufficient.
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Vulnerable FastAPI Security Lab",
    description="Intentionally insecure API used for security education.",
)

# VULNERABILITY (intentional — Security Misconfiguration, OWASP API8:2023):
# A wide-open CORS policy. allow_origins=["*"] together with
# allow_credentials=True makes Starlette REFLECT whatever Origin the caller
# sends and return Access-Control-Allow-Credentials: true, so a logged-in
# victim's browser on ANY site could read this API's authenticated
# responses cross-origin. No security headers are set either. (This CORS
# block is the ONLY change to the vulnerable app for this stage; its
# endpoints, auth, and authorization are untouched.)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(login.router)
app.include_router(users.router)
app.include_router(orders.router)
app.include_router(admin.router)


@app.get("/health")
def health_check():
    """Simple liveness check — confirms the app is running."""
    return {"status": "ok"}
