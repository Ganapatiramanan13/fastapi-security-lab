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
import jwt

import secure_app.main as secure_main
from secure_app.auth import JWT_ALGORITHM as SECURE_JWT_ALGORITHM
from secure_app.auth import JWT_SECRET_KEY as SECURE_JWT_SECRET_KEY
from secure_app.seed_data import seed as seed_secure

ALICE_USERNAME = "alice"
ALICE_PASSWORD = "alice_password123"

BOB_USERNAME = "bob"
BOB_PASSWORD = "bob_password123"

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin_password123"

# The VULNERABLE app's hardcoded secret. Used here only to prove
# secure_app does NOT accept tokens signed with it.
KNOWN_WEAK_SECRET = "supersecret"


@pytest.fixture(autouse=True)
def reset_secure_db():
    """Reset the database and rate-limit state before every test."""
    from secure_app.limiter import limiter

    limiter.reset()
    seed_secure()

@pytest.fixture
def client():
    return TestClient(secure_main.app)


def login_alice(client: TestClient) -> str:
    r = client.post("/login", json={"username": ALICE_USERNAME, "password": ALICE_PASSWORD})
    assert r.status_code == 200
    return r.json()["access_token"]


def login_as(client: TestClient, username: str, password: str) -> dict:
    """
    Log in as the given seeded user and return the full /login response
    body (access_token + user info), so callers can read the account's
    real id/role from the seed data instead of hardcoding either.
    """
    r = client.post("/login", json={"username": username, "password": password})
    assert r.status_code == 200
    return r.json()


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

    def test_admin_can_view_another_users_profile(self, client):
        """
        The admin-or-self rule in secure_app/routers/users.py should let
        an authenticated admin read ANY user's record, not just their
        own. Bob's id and the admin's role are both read from their own
        /login responses (seeded by secure_app/seed_data.py) rather than
        assumed, so this doesn't depend on a specific numeric id beyond
        what the seed data actually assigns.
        """
        bob_login = login_as(client, BOB_USERNAME, BOB_PASSWORD)
        bob_id = bob_login["user"]["id"]

        admin_login = login_as(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert admin_login["user"]["role"] == "admin"
        admin_token = admin_login["access_token"]

        r = client.get(f"/users/{bob_id}", headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 200
        assert r.json()["id"] == bob_id
        assert r.json()["username"] == "bob"


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
    def test_expired_token_is_rejected(self, client):
        """An expired JWT must return 401 Unauthorized."""
        claims = {
            "sub": "1",
            "username": "alice",
            "role": "user",
            "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
        }

        token = jwt.encode(
            claims,
            SECURE_JWT_SECRET_KEY,
            algorithm=SECURE_JWT_ALGORITHM,
        )

        r = client.get(
            "/users/1",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert r.status_code == 401
        assert r.json()["detail"] == "Could not validate credentials"
    def test_token_for_nonexistent_user_is_rejected(self, client):
        """A validly signed JWT for a nonexistent user must return 401."""
        claims = {
            "sub": "99999",
            "username": "ghost",
            "role": "user",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
        }

        token = jwt.encode(
            claims,
            SECURE_JWT_SECRET_KEY,
            algorithm=SECURE_JWT_ALGORITHM,
        )

        r = client.get(
            "/users/99999",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert r.status_code == 401
        assert r.json()["detail"] == "Could not validate credentials"

    def test_malformed_authorization_header_is_rejected(self, client):
        """An invalid Authorization header must return 401."""
        r = client.get(
            "/users/1",
            headers={"Authorization": "NotBearer token"},
        )

        assert r.status_code == 401
class TestLoginRateLimit:
    """Verify excessive login requests are rejected."""

    def test_login_rate_limit_returns_429(self, client):
        responses = [
            client.post(
                "/login",
                json={
                    "username": ALICE_USERNAME,
                    "password": "wrong_password",
                },
            )
            for _ in range(6)
        ]

        assert all(r.status_code == 401 for r in responses[:5])
        assert responses[5].status_code == 429


# ---------------------------------------------------------------------------
# SECURITY REGRESSION TEST: Improper Input Validation protection
#    (POST /orders, GET /orders/{order_id} — see secure_app/routers/orders.py)
# ---------------------------------------------------------------------------
class TestSecureInputValidation:
    """SECURITY REGRESSION TEST — a failure here means input validation regressed."""

    def test_valid_order_is_created_with_server_calculated_total(self, client):
        token = login_alice(client)
        headers = {"Authorization": f"Bearer {token}"}
        r = client.post(
            "/orders",
            headers=headers,
            json={"product": "Mouse", "quantity": 3, "unit_price": 10.0},
        )
        assert r.status_code == 201
        body = r.json()
        assert body["amount"] == 30.0
        assert body["user_id"] == 1
        assert body["quantity"] == 3

    def test_negative_quantity_is_rejected(self, client):
        token = login_alice(client)
        headers = {"Authorization": f"Bearer {token}"}
        r = client.post(
            "/orders",
            headers=headers,
            json={"product": "Mouse", "quantity": -5, "unit_price": 100.0},
        )
        assert r.status_code == 422

    def test_zero_quantity_is_rejected(self, client):
        token = login_alice(client)
        headers = {"Authorization": f"Bearer {token}"}
        r = client.post(
            "/orders",
            headers=headers,
            json={"product": "Mouse", "quantity": 0, "unit_price": 100.0},
        )
        assert r.status_code == 422

    def test_negative_price_is_rejected(self, client):
        token = login_alice(client)
        headers = {"Authorization": f"Bearer {token}"}
        r = client.post(
            "/orders",
            headers=headers,
            json={"product": "Mouse", "quantity": 1, "unit_price": -1.0},
        )
        assert r.status_code == 422

    def test_unexpected_field_is_rejected(self, client):
        """extra='forbid' — a client-supplied user_id (owner spoof) is a 422."""
        token = login_alice(client)
        headers = {"Authorization": f"Bearer {token}"}
        r = client.post(
            "/orders",
            headers=headers,
            json={"product": "Mouse", "quantity": 1, "unit_price": 5.0, "user_id": 2},
        )
        assert r.status_code == 422

    def test_malformed_json_does_not_500(self, client):
        token = login_alice(client)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        r = client.post("/orders", headers=headers, data="{not valid json")
        assert r.status_code == 422

    def test_missing_required_field_is_rejected(self, client):
        token = login_alice(client)
        headers = {"Authorization": f"Bearer {token}"}
        r = client.post(
            "/orders",
            headers=headers,
            json={"product": "Mouse", "unit_price": 5.0},
        )
        assert r.status_code == 422

    def test_owner_cannot_retrieve_another_users_order(self, client):
        a_token = login_alice(client)
        a_headers = {"Authorization": f"Bearer {a_token}"}
        created = client.post(
            "/orders",
            headers=a_headers,
            json={"product": "Mouse", "quantity": 1, "unit_price": 5.0},
        )
        assert created.status_code == 201
        order_id = created.json()["id"]

        bob = login_as(client, BOB_USERNAME, BOB_PASSWORD)
        b_headers = {"Authorization": f"Bearer {bob['access_token']}"}
        r = client.get(f"/orders/{order_id}", headers=b_headers)
        assert r.status_code == 403

        own = client.get(f"/orders/{order_id}", headers=a_headers)
        assert own.status_code == 200
        assert own.json()["id"] == order_id


# ---------------------------------------------------------------------------
# SECURITY REGRESSION TEST: non-finite / overflow numeric input (hardening)
#    (POST /orders — see secure_app/schemas.py: OrderCreate)
# ---------------------------------------------------------------------------
class TestSecureNonFiniteInputValidation:
    """
    Hardening for the Orders input-validation fix. Python's JSON parser
    (used by Starlette) accepts the non-standard literals NaN, Infinity and
    -Infinity, so those values DO reach the application; they must be
    rejected by the schema (allow_inf_nan=False / int typing / upper bound)
    with a 422, not reach the database and raise a 500.
    """

    def _post_raw(self, client, raw):
        token = login_alice(client)
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        return client.post("/orders", headers=headers, content=raw)

    def test_unit_price_nan_rejected_422(self, client):
        r = self._post_raw(client, '{"product": "M", "quantity": 1, "unit_price": NaN}')
        assert r.status_code == 422

    def test_unit_price_infinity_rejected_422(self, client):
        r = self._post_raw(client, '{"product": "M", "quantity": 1, "unit_price": Infinity}')
        assert r.status_code == 422

    def test_unit_price_negative_infinity_rejected_422(self, client):
        r = self._post_raw(client, '{"product": "M", "quantity": 1, "unit_price": -Infinity}')
        assert r.status_code == 422

    def test_non_finite_quantity_rejected_422(self, client):
        # quantity is an int field, so Infinity cannot be coerced to it.
        r = self._post_raw(client, '{"product": "M", "quantity": Infinity, "unit_price": 5.0}')
        assert r.status_code == 422

    def test_finite_overflow_unit_price_rejected_422(self, client):
        # 1e308 is finite but would overflow quantity*unit_price to inf;
        # the <= 1,000,000 upper bound rejects it.
        r = self._post_raw(client, '{"product": "M", "quantity": 1, "unit_price": 1e308}')
        assert r.status_code == 422

    def test_no_order_persisted_after_rejected_nonfinite(self, client):
        # Seed data creates orders with ids 1-3; a rejected request must not
        # create id 4. Verify as admin (who may read any order).
        self._post_raw(client, '{"product": "M", "quantity": 1, "unit_price": NaN}')
        admin = login_as(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        headers = {"Authorization": f"Bearer {admin['access_token']}"}
        r = client.get("/orders/4", headers=headers)
        assert r.status_code == 404

    def test_large_but_bounded_order_succeeds_with_finite_total(self, client):
        import math

        token = login_alice(client)
        headers = {"Authorization": f"Bearer {token}"}
        r = client.post(
            "/orders",
            headers=headers,
            json={"product": "M", "quantity": 1000000, "unit_price": 1000000.0},
        )
        assert r.status_code == 201
        amount = r.json()["amount"]
        assert amount == 1_000_000_000_000.0
        assert math.isfinite(amount)


# ---------------------------------------------------------------------------
# SECURITY REGRESSION TEST: Broken Function Level Authorization protection
#    (GET /admin/users — see secure_app/routers/admin.py)
# ---------------------------------------------------------------------------
class TestSecureFunctionLevelAuthProtection:
    """SECURITY REGRESSION TEST — a failure here means function-level authz regressed."""

    def test_ordinary_user_is_forbidden(self, client):
        token = login_alice(client)
        r = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

    def test_admin_can_list_all_users(self, client):
        admin = login_as(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        r = client.get(
            "/admin/users",
            headers={"Authorization": f"Bearer {admin['access_token']}"},
        )
        assert r.status_code == 200
        users = r.json()
        assert {"alice", "bob", "admin"} <= {u["username"] for u in users}
        assert all("password_hash" not in u for u in users)

    def test_missing_token_rejected(self, client):
        r = client.get("/admin/users")
        assert r.status_code == 401

    def test_invalid_token_rejected(self, client):
        r = client.get("/admin/users", headers={"Authorization": "Bearer not-a-real-token"})
        assert r.status_code == 401


def _add_dummy_users_secure(count, start_index=1000):
    """
    Insert throwaway users directly into the secure DB (dummy password_hash,
    never authenticated as) so pagination can be tested with more than the
    three seeded users. The autouse reset_secure_db fixture drops these rows
    before the next test.
    """
    from secure_app.database import SessionLocal
    from secure_app.models import User

    db = SessionLocal()
    try:
        for i in range(count):
            n = start_index + i
            db.add(User(
                username=f"load_user_{n}",
                email=f"load_user_{n}@example.com",
                password_hash="x",
                role="user",
            ))
        db.commit()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# SECURITY REGRESSION TEST: Unrestricted Resource Consumption protection
#    (GET /admin/users pagination — see secure_app/routers/admin.py, schemas)
# ---------------------------------------------------------------------------
class TestSecureResourceConsumption:
    """SECURITY REGRESSION TEST — a failure here means pagination/bounds regressed."""

    def _admin_headers(self, client):
        admin = login_as(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        return {"Authorization": f"Bearer {admin['access_token']}"}

    def test_default_limit_caps_results(self, client):
        _add_dummy_users_secure(50)  # 53 users total
        r = client.get("/admin/users", headers=self._admin_headers(client))
        assert r.status_code == 200
        assert len(r.json()) == 20  # default page size, not all 53

    def test_custom_limit_and_offset(self, client):
        _add_dummy_users_secure(50)
        h = self._admin_headers(client)
        page1 = client.get("/admin/users?limit=5&offset=0", headers=h)
        page2 = client.get("/admin/users?limit=5&offset=5", headers=h)
        assert page1.status_code == 200 and page2.status_code == 200
        ids1 = [u["id"] for u in page1.json()]
        ids2 = [u["id"] for u in page2.json()]
        assert len(ids1) == 5 and len(ids2) == 5
        assert ids1 == sorted(ids1)            # deterministic ordering
        assert set(ids1).isdisjoint(ids2)      # offset advances the window

    def test_limit_below_minimum_is_rejected(self, client):
        r = client.get("/admin/users?limit=0", headers=self._admin_headers(client))
        assert r.status_code == 422

    def test_limit_above_maximum_is_rejected(self, client):
        r = client.get("/admin/users?limit=101", headers=self._admin_headers(client))
        assert r.status_code == 422

    def test_negative_offset_is_rejected(self, client):
        r = client.get("/admin/users?offset=-1", headers=self._admin_headers(client))
        assert r.status_code == 422

    def test_admin_role_still_required_with_pagination(self, client):
        token = login_alice(client)
        r = client.get("/admin/users?limit=5&offset=0", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

    def test_missing_token_rejected(self, client):
        r = client.get("/admin/users?limit=5")
        assert r.status_code == 401

    def test_invalid_token_rejected(self, client):
        r = client.get("/admin/users?limit=5", headers={"Authorization": "Bearer not-a-real-token"})
        assert r.status_code == 401

    def test_no_password_hash_in_results(self, client):
        _add_dummy_users_secure(5)
        r = client.get("/admin/users", headers=self._admin_headers(client))
        assert r.status_code == 200
        assert all("password_hash" not in u for u in r.json())


# ---------------------------------------------------------------------------
# SECURITY REGRESSION TEST: Brute-Force Authentication protection
#    (POST /login rate limit — see secure_app/routers/login.py, limiter.py)
# ---------------------------------------------------------------------------
class TestSecureBruteForceProtection:
    """SECURITY REGRESSION TEST — a failure here means brute-force throttling regressed."""

    def test_rate_limit_blocks_after_five_failed_attempts(self, client):
        """
        The secure login is rate limited to 5 requests/minute per client IP.
        Five wrong-password attempts are processed (401); the sixth is
        throttled with 429 before the credentials are even checked, so an
        online brute force from one client IP is blunted. The autouse
        reset_secure_db fixture resets the limiter before each test, so this
        is deterministic and isolated (no timing dependence).
        """
        attempts = [
            client.post(
                "/login",
                json={"username": ALICE_USERNAME, "password": f"wrong-pw-{i}"},
            )
            for i in range(6)
        ]
        assert all(a.status_code == 401 for a in attempts[:5])  # first 5 rejected
        assert attempts[5].status_code == 429                   # 6th throttled
