
"""
Login router for the SECURE app.

Issues JWT tokens signed with the securely handled secret
and limits repeated login attempts.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from secure_app.limiter import limiter
from sqlalchemy.orm import Session

from secure_app.auth import authenticate_user, create_access_token
from secure_app.database import get_db
from secure_app.schemas import LoginRequest, LoginResponse, UserOut

router = APIRouter()




@router.post("/login", response_model=LoginResponse)
@limiter.limit("5/minute")
def login(
    request: Request,
    credentials: LoginRequest,
    db: Session = Depends(get_db),
):
    """Authenticate credentials and issue a JWT on success."""
    user = authenticate_user(
        db,
        credentials.username,
        credentials.password,
    )

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
        user=UserOut.model_validate(user),
    )
