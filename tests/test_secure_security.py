"""
Automated regression/security tests against the SECURE app.

These tests verify that the vulnerabilities demonstrated against
vulnerable_app (see test_vulnerable_security.py) are actually fixed
here. A failing test in this file represents a real security
regression, not an expected/documented behavior.

All requests go through FastAPI's TestClient, which calls the ASGI app
in-process (no real HTTP, no network sockets, no external hosts).
Requires SECURE_APP_JWT_SECRET to be set — see conftest.py, which sets
a fresh test-only secret before this module is imported.
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from jose import jwt

import secure_app.main as secure_main
from secure_app.auth import JWT_ALGORITHM as SECURE_JWT_ALGORITHM
from secure_app.auth import JWT_SECRET_KEY as SECURE_JWT_SECRET_KEY
from secure_app.seed_data import seed as seed_secure

ALICE_USERNAME = "alice"
ALICE_PASSWORD = "alice_password123"

# The VULNERABLE app's hardcoded secret. Used here only to prove
# secure_app does NOT accept tokens signed with it.
KNOWN_WEAK_SECRET = "supersecret"


@pytest.fixture(autouse=True)
def reset_secure_db():
    """Reseed the secure database before every test for a clean, deterministic state."""
    seed_secure()


@pytest.fixture
def client():
    return TestClient(secure_main.app)


def login_alice(client: TestClient) -> str:
    r = client.post("/login", json={"username": ALICE_USERNAME, "password": ALICE_PASSWORD})
    assert r.status_code == 200
    return r.json()["access_token"]


def forge_token_with_weak_secret(sub: str, username: str, role: str) -> str:
    """Build a JWT signed with the vulnerable app's known weak secret."""
    claims = {
        "sub": sub,
        "username": username,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
    }
    return jwt.encode(claims, KNOWN_WEAK_SECRET, algorithm="HS256")


# ---------------------------------------------------------------------------
# 4. SECURITY REGRESSION TEST: BOLA protection
#    (GET /users/{user_id} — see secure_app/routers/users.py)
# ---------------------------------------------------------------------------
class TestSecureBOLAProtection:
    """SECURITY REGRESSION TEST — a failure here means BOLA protection regressed."""

    def test_alice_can_view_her_own_profile(self, client):
        token = login_alice(client)
        r = client.get("/users/1", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json()["id"] == 1

    def test_alice_cannot_view_bobs_profile(self, client):
        token = login_alice(client)
        r = client.get("/users/2", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# 5. SECURITY REGRESSION TEST: Mass Assignment protection
#    (PUT /users/{user_id} — see secure_app/routers/users.py, schemas.py)
# ---------------------------------------------------------------------------
class TestSecureMassAssignmentProtection:
    """SECURITY REGRESSION TEST — a failure here means Mass Assignment protection regressed."""

    def test_alice_can_update_her_own_email(self, client):
        token = login_alice(client)
        headers = {"Authorization": f"Bearer {token}"}
        r = client.put("/users/1", headers=headers, json={"email": "alice_secure@example.com"})
        assert r.status_code == 200
        assert r.json()["email"] == "alice_secure@example.com"
        assert r.json()["role"] == "user"

    def test_role_field_is_rejected_by_schema(self, client):
        """UserUpdate uses extra='forbid' — an unknown "role" field is a 422, not applied."""
        token = login_alice(client)
        headers = {"Authorization": f"Bearer {token}"}
        r = client.put(
            "/users/1",
            headers=headers,
            json={"email": "another@example.com", "role": "admin"},
        )
        assert r.status_code == 422

    def test_alice_role_remains_user_after_attempted_escalation(self, client):
        token = login_alice(client)
        headers = {"Authorization": f"Bearer {token}"}
        client.put("/users/1", headers=headers, json={"email": "x@example.com", "role": "admin"})

        r = client.get("/users/1", headers=headers)
        assert r.status_code == 200
        assert r.json()["role"] == "user"


# ---------------------------------------------------------------------------
# 6. SECURITY REGRESSION TEST: Weak JWT protection
#    (GET /admin — see secure_app/auth.py, JWT_SECRET_KEY handling)
# ---------------------------------------------------------------------------
class TestSecureWeakJWTProtection:
    """SECURITY REGRESSION TEST — a failure here means the JWT secret fix regressed."""

    def test_alice_legitimate_token_cannot_access_admin(self, client):
        token = login_alice(client)
        r = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

    def test_token_forged_with_vulnerable_secret_is_rejected(self, client):
        """
        A token signed with the vulnerable app's known secret
        ("supersecret") must fail signature verification here, since
        secure_app signs with its own independent, high-entropy secret.
        """
        forged_token = forge_token_with_weak_secret(sub="3", username="admin", role="admin")
        r = client.get("/admin", headers={"Authorization": f"Bearer {forged_token}"})
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# REGRESSION TEST: non-numeric "sub" claim must not crash get_current_user()
#    (see secure_app/auth.py — int(user_id) is now inside the try/except
#    so a bad "sub" returns 401, not an unhandled 500)
# ---------------------------------------------------------------------------
class TestGetCurrentUserRobustness:
    """SECURITY REGRESSION TEST — a non-numeric "sub" must yield 401, not 500."""

    def test_non_numeric_sub_returns_401_not_500(self, client):
        """
        Sign a token with secure_app's OWN real secret (imported
        directly from secure_app.auth, never printed) so it passes
        signature verification and actually reaches the int(user_id)
        conversion. A non-numeric "sub" used to raise an unhandled
        ValueError there, surfacing as a raw 500. It must now be
        rejected cleanly with 401, like any other malformed token.
        """
        claims = {
            "sub": "not-a-number",
            "username": "alice",
            "role": "user",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
        }
        token = jwt.encode(claims, SECURE_JWT_SECRET_KEY, algorithm=SECURE_JWT_ALGORITHM)

        r = client.get("/users/1", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401
        assert r.json()["detail"] == "Could not validate credentials"


# ---------------------------------------------------------------------------
# 7. Authentication regression tests
# ---------------------------------------------------------------------------
class TestAuthenticationRegression:
    """SECURITY REGRESSION TEST — basic login/auth behavior must not break."""

    def test_valid_login_succeeds(self, client):
        r = client.post("/login", json={"username": ALICE_USERNAME, "password": ALICE_PASSWORD})
        assert r.status_code == 200
        assert "access_token" in r.json()

    def test_wrong_password_rejected(self, client):
        r = client.post("/login", json={"username": ALICE_USERNAME, "password": "wrong"})
        assert r.status_code == 401

    def test_missing_token_rejected(self, client):
        r = client.get("/users/1")
        assert r.status_code == 401

    def test_invalid_token_rejected(self, client):
        r = client.get("/users/1", headers={"Authorization": "Bearer not-a-real-token"})
        assert r.status_code == 401
