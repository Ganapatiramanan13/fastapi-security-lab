"""
Authentication helpers for the SECURE app.

Mirrors vulnerable_app/auth.py structurally (bcrypt password checks +
JWT issuing/verification, same HS256 algorithm — no authentication
redesign here), but fixes the "Weak JWT Implementation" vulnerability
studied in the vulnerable app:

FIX (compare to vulnerable_app.auth.JWT_SECRET_KEY = "supersecret"):
  - The signing secret is NEVER hardcoded in source.
  - It is read exclusively from the SECURE_APP_JWT_SECRET environment
    variable, which is never committed to source control (.gitignore
    already excludes .env files; no default value lives in this repo).
  - If that variable is missing, or present but too short/weak to be a
    real secret, the app FAILS TO START — it raises immediately at
    import time rather than silently substituting any value (weak,
    hardcoded, or even an auto-generated one). A loud startup failure
    is the correct behavior for a missing secret: it forces whoever is
    deploying this to consciously set one, instead of the app quietly
    running in a less-secure state nobody notices.
  - In a real deployment, SECURE_APP_JWT_SECRET would be set from a
    proper secrets manager, kept stable across restarts/replicas, and
    rotated periodically.

To run this app locally, set a strong secret first, e.g.:
    export SECURE_APP_JWT_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")
"""

import os
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from secure_app.database import get_db
from secure_app.models import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- Secure JWT configuration -------------------------------------------
# Never hardcode a real secret, and never fall back to a predictable or
# silently-generated default. Require an explicit, sufficiently long
# secret from the environment — fail fast (refuse to start) otherwise.
_MIN_SECRET_LENGTH = 32  # characters; e.g. secrets.token_hex(16) or longer

JWT_SECRET_KEY = os.environ.get("SECURE_APP_JWT_SECRET")

if not JWT_SECRET_KEY:
    raise RuntimeError(
        "SECURE_APP_JWT_SECRET environment variable is not set. "
        "Refusing to start with no JWT signing secret. Set a strong, "
        "random secret before starting the app, e.g.:\n"
        '    export SECURE_APP_JWT_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")'
    )

if len(JWT_SECRET_KEY) < _MIN_SECRET_LENGTH:
    raise RuntimeError(
        f"SECURE_APP_JWT_SECRET is only {len(JWT_SECRET_KEY)} characters long; "
        f"refusing to start with a JWT secret shorter than {_MIN_SECRET_LENGTH} "
        "characters, since a short secret can be brute-forced."
    )

JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Check a plaintext password against a stored bcrypt hash."""
    return pwd_context.verify(plain_password, password_hash)


def get_user_by_username(db: Session, username: str) -> User | None:
    """Look up a user by their username. Returns None if not found."""
    return db.query(User).filter(User.username == username).first()


def authenticate_user(db: Session, username: str, password: str) -> User | None:
    """
    Attempt to authenticate a user. Returns the User on success, or
    None if the username doesn't exist OR the password is wrong (the
    router turns both into the same generic 401).
    """
    user = get_user_by_username(db, username)
    if user is None:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def create_access_token(user: User) -> str:
    """Build a signed JWT for an authenticated user."""
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
    Reusable FastAPI dependency: decodes/verifies the JWT and loads the
    corresponding user. Raises 401 if the token is missing, malformed,
    expired, incorrectly signed, or refers to a user that no longer
    exists.

    Like the vulnerable app's version, this only proves "this is a
    validly-signed token for some user" (authentication). It does not
    decide whether that user is allowed to access a particular object —
    that's enforced separately, per-endpoint (see routers/users.py for
    the object-level authorization check).
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
