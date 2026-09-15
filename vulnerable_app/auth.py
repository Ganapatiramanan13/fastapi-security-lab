"""
Authentication helpers for the VULNERABLE app.

Stage 3 added password verification. Stage 4 (this update) adds JWT
issuing and decoding so /login can hand back an access token, and so
future protected endpoints have a reusable way to identify the caller.

Because there is still no rate limiting or account lockout here, a
determined attacker could call authenticate_user() as many times as they
want with different passwords (brute force). That's intentional for now
— "Missing Rate Limiting" is its own vulnerability category we'll study
and exploit later.

VULNERABILITY (intentional, Stage 4 — "Weak JWT Implementation"):
JWT_SECRET_KEY below is short, guessable, and hard-coded directly in the
source file. See the long comment above that constant for exactly why
this is dangerous. This will be exploited and then fixed in later
stages — it is left in on purpose so we can study it.
"""

from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from vulnerable_app.database import get_db
from vulnerable_app.models import User

# CryptContext handles hashing and verifying bcrypt hashes for us.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ---------------------------------------------------------------------------
# INTENTIONALLY WEAK JWT CONFIGURATION — DO NOT COPY INTO A REAL PROJECT
# ---------------------------------------------------------------------------
# This secret is:
#   - short and made of dictionary words, so it's crackable by brute force
#     or a wordlist in a realistic amount of time,
#   - hard-coded directly in source, so anyone who reads this file (or the
#     public GitHub repo this project will live in) has it too,
#   - never loaded from an environment variable or secrets manager, and
#   - never rotated.
#
# Whoever holds this secret can forge a JWT for ANY user (including
# role="admin") without ever knowing that user's password, and every
# endpoint that trusts this token will accept it as genuine. That's the
# vulnerability we want to demonstrate and later fix (e.g. by loading a
# long, random secret from the environment and keeping it out of source
# control).
JWT_SECRET_KEY = "supersecret"
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 30

# Tells FastAPI's docs/OpenAPI UI where clients send credentials to get a
# token, and lets us extract "Authorization: Bearer <token>" from
# incoming requests via Depends(oauth2_scheme).
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def verify_password(plain_password: str, password_hash: str) -> bool:
    """
    Check a plaintext password against a stored bcrypt hash.

    We never compare plaintext passwords directly (that would require
    storing plaintext, which we never do) — bcrypt re-hashes the
    supplied password with the same salt and compares the result.
    """
    return pwd_context.verify(plain_password, password_hash)


def get_user_by_username(db: Session, username: str) -> User | None:
    """Look up a user by their username. Returns None if not found."""
    return db.query(User).filter(User.username == username).first()


def authenticate_user(db: Session, username: str, password: str) -> User | None:
    """
    Attempt to authenticate a user.

    Returns the User object on success, or None if the username doesn't
    exist OR the password is wrong. We deliberately don't distinguish
    between "user not found" and "wrong password" in the return value —
    the router turns both into the same generic 401, so this function
    alone doesn't leak which one occurred.
    """
    user = get_user_by_username(db, username)
    if user is None:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def create_access_token(user: User) -> str:
    """
    Build a signed JWT for an authenticated user.

    Claims included (kept intentionally minimal for this stage):
      - sub: the user's ID, as a string (JWT spec expects "sub" to be a
        string, even though our IDs are ints)
      - username: for convenience, so callers don't need a DB lookup
        just to display who they're logged in as
      - role: used later by authorization checks on protected endpoints
      - exp: standard JWT expiry claim, checked automatically by
        jose.jwt.decode()

    No refresh token, no "iat"/"nbf", no algorithm-confusion handling —
    all deliberately out of scope for this stage.
    """
    expire = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    claims = {
        "sub": str(user.id),
        "username": user.username,
        "role": user.role,
        "exp": expire,
    }
    return jwt.encode(claims, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """
    Reusable FastAPI dependency for protected endpoints.

    Decodes and verifies the JWT from the "Authorization: Bearer <token>"
    header, then loads the corresponding user from the database. Raises
    HTTP 401 if the token is missing, malformed, expired, incorrectly
    signed, or refers to a user that no longer exists.

    Endpoints in later stages will use this as:
        def some_endpoint(current_user: User = Depends(get_current_user)):
            ...

    Note: at this stage this function only proves "this token is a
    validly-signed JWT for some user." It does NOT check whether that
    user is allowed to do whatever the endpoint is about to do —
    authorization checks are a separate, later stage.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        # A malformed/forged token can carry a non-numeric "sub" — catch
        # that here (ValueError) alongside JWTError, so it becomes a
        # clean 401 instead of an unhandled 500.
        user_id = int(user_id)
    except (JWTError, ValueError):
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception

    return user
