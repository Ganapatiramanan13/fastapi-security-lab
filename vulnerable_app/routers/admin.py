"""
Admin router for the VULNERABLE app.

Exposes GET /admin — the first endpoint in this app whose authorization
decision actually depends on the JWT's "role" claim. Earlier endpoints
(GET/PUT /users/{user_id}) never looked at role at all; this one exists
specifically so the "Weak JWT Implementation" vulnerability (a
hardcoded, guessable signing secret — see auth.py) has something real
to unlock: a forged role="admin" claim should let an attacker in here
even though they never authenticated as an actual admin.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from vulnerable_app.auth import get_current_user
from vulnerable_app.database import get_db
from vulnerable_app.models import User
from vulnerable_app.schemas import UserOut

router = APIRouter()


@router.get("/admin")
def admin_dashboard(current_user: User = Depends(get_current_user)):
    """
    A minimal admin-only endpoint.

    Authorization here is correctly role-based for a LEGITIMATE token:
    only current_user.role == "admin" is allowed through, everyone else
    gets 403. The vulnerability is not in this check — it's that the
    JWT this check relies on can be forged (see auth.py's
    JWT_SECRET_KEY). A signature check can only prove "this token was
    signed with JWT_SECRET_KEY" — it says nothing about who actually
    typed a password, if the secret itself is not actually secret.
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

    VULNERABILITY (intentional — Broken Function Level Authorization,
    OWASP API5:2023 / CWE-285): this endpoint checks only that the caller
    is AUTHENTICATED (a valid JWT via get_current_user); it never checks
    that the caller holds the admin ROLE. Compare GET /admin above, which
    DOES check current_user.role. Because that function-level check is
    simply missing here, ANY logged-in user — including an ordinary
    "user" — can call this admin-only function and enumerate every
    account (usernames, emails, roles).

    The response schema is still UserOut, so password hashes are never
    exposed: the flaw demonstrated here is the MISSING AUTHORIZATION on a
    privileged function, not sensitive-field leakage.
    """
    return db.query(User).all()
