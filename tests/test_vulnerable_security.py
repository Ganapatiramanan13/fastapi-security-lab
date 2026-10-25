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
import jwt

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


# ---------------------------------------------------------------------------
# INTENTIONAL VULNERABILITY DEMONSTRATION: Improper Input Validation
#    (POST /orders — see vulnerable_app/routers/orders.py, schemas.py)
# ---------------------------------------------------------------------------
class TestVulnerableInputValidation:
    """INTENTIONAL VULNERABILITY DEMONSTRATION — not a security guarantee."""

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
        assert body["amount"] == 30.0        # total computed server-side
        assert body["user_id"] == 1          # owner derived from the token (Alice)
        assert body["quantity"] == 3

    def test_negative_quantity_is_accepted_and_persists_negative_total(self, client):
        """
        INTENTIONAL VULNERABILITY: the vulnerable schema puts no lower bound
        on quantity, so quantity=-5 is accepted and a negative total (-500)
        is computed and persisted — a clear data-integrity violation.
        """
        token = login_alice(client)
        headers = {"Authorization": f"Bearer {token}"}
        r = client.post(
            "/orders",
            headers=headers,
            json={"product": "Mouse", "quantity": -5, "unit_price": 100.0},
        )
        assert r.status_code == 201
        assert r.json()["amount"] == -500.0
        order_id = r.json()["id"]

        g = client.get(f"/orders/{order_id}", headers=headers)
        assert g.status_code == 200
        assert g.json()["amount"] == -500.0

    def test_client_cannot_choose_order_owner(self, client):
        """
        Even the vulnerable endpoint derives the owner from the token, so a
        client-supplied user_id is ignored (not an owner-spoofing flaw).
        """
        token = login_alice(client)
        headers = {"Authorization": f"Bearer {token}"}
        r = client.post(
            "/orders",
            headers=headers,
            json={"product": "Mouse", "quantity": 1, "unit_price": 5.0, "user_id": 2},
        )
        assert r.status_code == 201
        assert r.json()["user_id"] == 1      # Alice, not the injected 2


# ---------------------------------------------------------------------------
# INTENTIONAL VULNERABILITY DEMONSTRATION: Broken Function Level Authorization
#    (GET /admin/users — see vulnerable_app/routers/admin.py)
# ---------------------------------------------------------------------------
class TestVulnerableBrokenFunctionLevelAuth:
    """INTENTIONAL VULNERABILITY DEMONSTRATION — not a security guarantee."""

    def test_ordinary_user_can_list_all_users_bfla(self, client):
        """
        INTENTIONAL VULNERABILITY: an ordinary user (Alice, role "user")
        calls the admin-only GET /admin/users and receives 200 with every
        account, because the endpoint never checks the admin role.
        """
        token = login_alice(client)
        r = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        users = r.json()
        usernames = {u["username"] for u in users}
        assert {"alice", "bob", "admin"} <= usernames
        assert all("password_hash" not in u for u in users)

    def test_admin_can_list_all_users(self, client):
        r = client.post("/login", json={"username": "admin", "password": "admin_password123"})
        assert r.status_code == 200
        token = r.json()["access_token"]
        r = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert len(r.json()) >= 3

    def test_missing_token_rejected(self, client):
        r = client.get("/admin/users")
        assert r.status_code == 401

    def test_invalid_token_rejected(self, client):
        r = client.get("/admin/users", headers={"Authorization": "Bearer not-a-real-token"})
        assert r.status_code == 401


def _add_dummy_users_vuln(count, start_index=1000):
    """
    Insert throwaway users directly into the vulnerable DB to prove the
    admin-users list is unbounded. password_hash is a dummy value (these
    rows are only ever listed, never authenticated as), so no bcrypt cost
    is incurred. The autouse reseed fixture drops these rows before the
    next test, so no cleanup is needed here.
    """
    from vulnerable_app.database import SessionLocal
    from vulnerable_app.models import User

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
# INTENTIONAL VULNERABILITY DEMONSTRATION: Unrestricted Resource Consumption
#    (GET /admin/users — see vulnerable_app/routers/admin.py)
# ---------------------------------------------------------------------------
class TestVulnerableResourceConsumption:
    """INTENTIONAL VULNERABILITY DEMONSTRATION — not a security guarantee."""

    def test_admin_users_list_is_unbounded(self, client):
        """
        INTENTIONAL VULNERABILITY: with 150 extra users inserted, the
        endpoint returns all 153 accounts in a single response — no page
        size cap at all (not even the 100 the secure app enforces).
        """
        _add_dummy_users_vuln(150)
        token = login_alice(client)
        r = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert len(r.json()) == 153

    def test_admin_users_ignores_limit_query_param(self, client):
        """
        The vulnerable endpoint has no pagination parameters, so a client's
        ?limit=1 is silently ignored and the full list is still returned.
        """
        _add_dummy_users_vuln(150)
        token = login_alice(client)
        r = client.get("/admin/users?limit=1", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert len(r.json()) == 153


# ---------------------------------------------------------------------------
# INTENTIONAL VULNERABILITY DEMONSTRATION: Brute-Force Authentication
#    (POST /login — see vulnerable_app/routers/login.py: no throttling)
# ---------------------------------------------------------------------------
class TestVulnerableBruteForce:
    """INTENTIONAL VULNERABILITY DEMONSTRATION — not a security guarantee."""

    def test_unlimited_failed_attempts_then_correct_login_succeeds(self, client):
        """
        INTENTIONAL VULNERABILITY: 15 wrong-password attempts against a real
        seeded user are all answered 401 with no throttling (no 429), and the
        correct password still works immediately afterwards — proving there
        is neither rate limiting nor account lockout.
        """
        responses = [
            client.post(
                "/login",
                json={"username": ALICE_USERNAME, "password": f"wrong-pw-{i}"},
            )
            for i in range(15)
        ]
        assert all(r.status_code == 401 for r in responses)   # every attempt rejected
        assert all(r.status_code != 429 for r in responses)   # never throttled

        # No account lockout: the correct password still works afterwards.
        ok = client.post(
            "/login",
            json={"username": ALICE_USERNAME, "password": ALICE_PASSWORD},
        )
        assert ok.status_code == 200
        assert "access_token" in ok.json()

    def test_nonexistent_user_returns_generic_401(self, client):
        """
        A guess for an unknown username is rejected with the same generic 401
        message as a wrong password, so the response does not disclose whether
        the account exists.
        """
        r = client.post(
            "/login",
            json={"username": "ghost_user_xyz", "password": "irrelevant"},
        )
        assert r.status_code == 401
        assert r.json()["detail"] == "Invalid username or password"


# ---------------------------------------------------------------------------
# INTENTIONAL VULNERABILITY DEMONSTRATION: Security Misconfiguration (CORS)
#    (app-level CORS — see vulnerable_app/main.py)
# ---------------------------------------------------------------------------
class TestVulnerableSecurityMisconfiguration:
    """INTENTIONAL VULNERABILITY DEMONSTRATION — not a security guarantee.

    NOTE: TestClient reports the HEADERS THE SERVER SENDS; it does not enforce
    the browser's same-origin policy. These assertions therefore show the
    server misconfiguration (a permissive CORS response), which is what a real
    browser would act on, not the browser enforcement itself.
    """

    def test_permissive_cors_reflects_any_origin_with_credentials(self, client):
        evil = "https://evil.example"
        r = client.get("/health", headers={"Origin": evil})
        assert r.status_code == 200
        # allow_origins=["*"] + allow_credentials=True makes Starlette reflect
        # the caller's Origin (not literal "*") and allow credentials.
        assert r.headers.get("access-control-allow-origin") == evil
        assert r.headers.get("access-control-allow-credentials") == "true"

    def test_no_security_headers_present(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        for h in (
            "x-content-type-options",
            "x-frame-options",
            "content-security-policy",
            "referrer-policy",
        ):
            assert h not in r.headers


def _forge_alg_none(sub, username="admin", role="admin", exp=None, nbf=None,
                    include_exp=True):
    """
    Build an UNSIGNED JWT (alg:none) with attacker-chosen claims. No signing
    secret is used or needed — that is the whole point of the alg:none attack.
    exp defaults to 30 minutes in the future; pass exp/nbf to exercise the
    time-based claim validation that the vulnerable path still enforces. Pass
    include_exp=False to omit the exp claim entirely and exercise the required
    -exp check.
    """
    now = datetime.now(timezone.utc)
    claims = {
        "sub": sub,
        "username": username,
        "role": role,
    }
    if include_exp:
        claims["exp"] = exp if exp is not None else now + timedelta(minutes=30)
    if nbf is not None:
        claims["nbf"] = nbf
    return jwt.encode(claims, key="", algorithm="none")


# ---------------------------------------------------------------------------
# INTENTIONAL VULNERABILITY DEMONSTRATION: JWT algorithm-verification (alg:none)
#    (GET /admin via get_current_user — see vulnerable_app/auth.py)
# ---------------------------------------------------------------------------
class TestVulnerableJwtAlgNone:
    """INTENTIONAL VULNERABILITY DEMONSTRATION — not a security guarantee."""

    def test_alg_none_token_impersonates_admin_without_secret(self, client):
        """
        INTENTIONAL VULNERABILITY: an unsigned alg:none token with sub="3"
        (the seeded admin's real id) is accepted and grants admin access,
        without the attacker ever knowing the signing secret.
        """
        forged = _forge_alg_none(sub="3")
        r = client.get("/admin", headers={"Authorization": f"Bearer {forged}"})
        assert r.status_code == 200
        assert r.json()["message"] == "Welcome to the admin area"

    def test_hs256_signature_still_enforced(self, client):
        """
        The flaw is scoped to alg:none: a normal HS256 token signed with the
        WRONG secret is still rejected, proving signature verification is not
        globally disabled.
        """
        bad = jwt.encode(
            {"sub": "3", "role": "admin", "exp": datetime.now(timezone.utc) + timedelta(minutes=30)},
            "not-the-real-secret",
            algorithm="HS256",
        )
        r = client.get("/admin", headers={"Authorization": f"Bearer {bad}"})
        assert r.status_code == 401

    def test_legitimate_login_token_still_works(self, client):
        """A real HS256 token from /login still authenticates normally."""
        token = login_alice(client)
        r = client.get("/users/1", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json()["id"] == 1

    def test_alg_none_non_numeric_sub_still_401(self, client):
        """Malformed/non-numeric sub handling is preserved even on the alg:none path."""
        forged = _forge_alg_none(sub="not-a-number")
        r = client.get("/admin", headers={"Authorization": f"Bearer {forged}"})
        assert r.status_code == 401
        assert r.json()["detail"] == "Could not validate credentials"

    def test_expired_alg_none_token_rejected(self, client):
        """
        Time-based validation is kept ON for the alg:none path: an unsigned
        token with an expired exp is rejected (401), not accepted — the flaw
        is isolated to signature verification.
        """
        forged = _forge_alg_none(
            sub="3", exp=datetime.now(timezone.utc) - timedelta(minutes=5)
        )
        r = client.get("/admin", headers={"Authorization": f"Bearer {forged}"})
        assert r.status_code == 401
        assert r.json()["detail"] == "Could not validate credentials"

    def test_future_nbf_alg_none_token_rejected(self, client):
        """An unsigned token that is not yet valid (future nbf) is rejected (401)."""
        now = datetime.now(timezone.utc)
        forged = _forge_alg_none(
            sub="3", exp=now + timedelta(minutes=30), nbf=now + timedelta(minutes=10)
        )
        r = client.get("/admin", headers={"Authorization": f"Bearer {forged}"})
        assert r.status_code == 401
        assert r.json()["detail"] == "Could not validate credentials"

    def test_missing_exp_alg_none_token_rejected(self, client):
        """
        The vulnerable alg:none path requires an exp claim (require=["exp"]):
        a structurally valid unsigned token with NO exp is rejected (401),
        not accepted — the signature flaw does not also disable claim
        requirements.
        """
        forged = _forge_alg_none(sub="3", include_exp=False)
        r = client.get("/admin", headers={"Authorization": f"Bearer {forged}"})
        assert r.status_code == 401
        assert r.json()["detail"] == "Could not validate credentials"
