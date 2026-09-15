"""
Login router for the SECURE app.

Same shape as vulnerable_app/routers/login.py, but issues tokens signed
with the securely-handled secret from secure_app/auth.py.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from secure_app.auth import authenticate_user, create_access_token
from secure_app.database import get_db
from secure_app.schemas import LoginRequest, LoginResponse

router = APIRouter()


@router.post("/login", response_model=LoginResponse)
def login(credentials: LoginRequest, db: Session = Depends(get_db)):
    """
    Verify a username/password pair and, on success, issue a JWT
    access token. Same generic 401 on failure regardless of whether the
    username exists or the password was wrong.
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
