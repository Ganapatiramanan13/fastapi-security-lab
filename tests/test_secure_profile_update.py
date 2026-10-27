"""
Focused tests for secure_app's profile-update error handling.

Covers PUT /users/{user_id}:
  - duplicate username -> 409 (not 500), transaction rolled back
  - duplicate email    -> 409
  - a rejected update leaves the DB usable (a later valid update works)
  - empty username rejected by request validation (422)
  - a normal valid update still succeeds

Database isolation:
  This file NEVER imports secure_app.main (whose module-level
  Base.metadata.create_all would connect to the real ./secure_app/secure.db).
  It imports only the users router plus Base/get_db/get_current_user, none of
  which open a connection at import time (the module-level engine is lazy and
  is never used here). Each test runs against a fresh temporary SQLite file
  under pytest's tmp_path, with get_db overridden to that temp engine and
  get_current_user overridden to a stub — so no JWT/login flow is needed and
  neither real database (secure.db / vulnerable.db) is read or written. This
  file defines no autouse fixtures and does not import the real-DB
  reset/reseed fixtures from test_secure_security.py.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from secure_app.auth import get_current_user
from secure_app.database import Base, get_db
from secure_app.models import User
from secure_app.routers import users as users_router


class _StubUser:
    """Minimal stand-in for an authenticated User (endpoint uses .id/.role)."""

    def __init__(self, id: int, role: str):
        self.id = id
        self.role = role


@pytest.fixture
def client_and_session(tmp_path):
    db_path = tmp_path / "secure_test.db"
    engine = create_engine(
        "sqlite:///" + db_path.as_posix(),
        connect_args={"check_same_thread": False},
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    # Seed two users directly in the ISOLATED temp DB (dummy hash — this
    # endpoint never checks the password).
    seed = TestingSessionLocal()
    try:
        seed.add_all([
            User(id=1, username="alice", email="alice@example.com",
                 password_hash="x", role="user"),
            User(id=2, username="bob", email="bob@example.com",
                 password_hash="x", role="user"),
        ])
        seed.commit()
    finally:
        seed.close()

    app = FastAPI()
    app.include_router(users_router.router)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    # Authenticate every request as alice (id=1, ordinary user), bypassing
    # the JWT/login flow entirely.
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = lambda: _StubUser(id=1, role="user")

    client = TestClient(app)
    try:
        yield client, TestingSessionLocal
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


class TestSecureProfileUpdate:
    def test_duplicate_username_returns_409(self, client_and_session):
        client, _ = client_and_session
        r = client.put("/users/1", json={"username": "bob"})  # bob already exists
        assert r.status_code == 409
        assert r.json()["detail"] == "Username or email already in use"
        # No SQL/database internals leaked in the response body.
        body = r.text.lower()
        for leak in ("integrityerror", "sqlite", "unique constraint", "traceback"):
            assert leak not in body

    def test_duplicate_email_returns_409(self, client_and_session):
        client, _ = client_and_session
        r = client.put("/users/1", json={"email": "bob@example.com"})
        assert r.status_code == 409
        assert r.json()["detail"] == "Username or email already in use"

    def test_rejected_update_leaves_db_usable(self, client_and_session):
        client, SessionLocal = client_and_session
        # A duplicate must 409 and roll back, not corrupt the session.
        r1 = client.put("/users/1", json={"username": "bob"})
        assert r1.status_code == 409
        # alice's row is unchanged in the isolated DB.
        s = SessionLocal()
        try:
            alice = s.query(User).filter(User.id == 1).first()
            assert alice.username == "alice"
        finally:
            s.close()
        # A subsequent valid update still works (DB/session remain usable).
        r2 = client.put("/users/1", json={"username": "alice_renamed"})
        assert r2.status_code == 200
        assert r2.json()["username"] == "alice_renamed"

    def test_empty_username_rejected_422(self, client_and_session):
        client, _ = client_and_session
        r = client.put("/users/1", json={"username": ""})
        assert r.status_code == 422

    def test_valid_update_succeeds(self, client_and_session):
        client, _ = client_and_session
        r = client.put(
            "/users/1",
            json={"username": "alice2", "email": "alice2@example.com"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["username"] == "alice2"
        assert data["email"] == "alice2@example.com"
        assert data["role"] == "user"  # role is not client-writable here
