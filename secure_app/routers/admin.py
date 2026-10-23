"""
Admin router for the SECURE app.

Mirrors vulnerable_app/routers/admin.py — same route, same role check —
so the fixed JWT implementation can be tested against the exact same
attack (forged role/identity claims) that succeeded against the
vulnerable app in exploits/exploit_weak_jwt.py.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from secure_app.auth import get_current_user
from secure_app.database import get_db
from secure_app.models import User
from secure_app.schemas import UserOut

router = APIRouter()


@router.get("/admin")
def admin_dashboard(current_user: User = Depends(get_current_user)):
    """
    Admin-only endpoint. Only current_user.role == "admin" is allowed
    through; everyone else gets 403. Because get_current_user() only
    accepts tokens signed with the real SECURE_APP_JWT_SECRET (never
    hardcoded, never guessable), a token forged with the vulnerable
    app's known secret ("supersecret") will fail signature verification
    and never even reach this check — it gets rejected as 401 first.
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    return {"message": "Welcome to the admin area"}

@router.get("/admin/users", response_model=list[UserOut])
def list_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    List every user — an administrative function.

    FIX (compare to vulnerable_app — Broken Function Level
    Authorization, OWASP API5:2023 / CWE-285): the function-level
    authorization check that the vulnerable app omits is enforced here.
    Only a caller whose role is "admin" may invoke this endpoint; every
    other authenticated caller receives 403 BEFORE any user data is read.
    Authentication alone (a valid token) is never sufficient for a
    privileged function.
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return db.query(User).all()
