"""
Login router for the VULNERABLE app.

Exposes a single endpoint: POST /login. Kept deliberately simple at this
stage — see auth.py and schemas.py for notes on what's intentionally
missing (rate limiting, lockout, tokens) and why.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from vulnerable_app.auth import authenticate_user, create_access_token
from vulnerable_app.database import get_db
from vulnerable_app.schemas import LoginRequest, LoginResponse

router = APIRouter()


@router.post("/login", response_model=LoginResponse)
def login(credentials: LoginRequest, db: Session = Depends(get_db)):
    """
    Verify a username/password pair against the database and, on
    success, issue a JWT access token.

    - On success: HTTP 200 with a signed JWT (see auth.create_access_token)
      plus basic account info.
    - On failure (unknown username OR wrong password): HTTP 401 with a
      generic error message. We use the same message for both cases so
      the response itself doesn't reveal whether the username exists.
    """
    user = authenticate_user(db, credentials.username, credentials.password)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    access_token = create_access_token(user)

    return LoginResponse(
        message="Login successful",
        access_token=access_token,
        token_type="bearer",
        user=user,
    )
