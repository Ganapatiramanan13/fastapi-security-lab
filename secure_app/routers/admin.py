"""
Admin router for the SECURE app.

Mirrors vulnerable_app/routers/admin.py — same route, same role check —
so the fixed JWT implementation can be tested against the exact same
attack (forged role/identity claims) that succeeded against the
vulnerable app in exploits/exploit_weak_jwt.py.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
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
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """
    List users — an administrative function, with bounded pagination.

    FIX (Broken Function Level Authorization, OWASP API5:2023 /
    CWE-285): the admin-role check the vulnerable app omits is enforced
    here; only an "admin" caller may invoke this endpoint (403
    otherwise), before any data is read.

    FIX (Unrestricted Resource Consumption, OWASP API4:2023): the result
    set is bounded. `limit` is validated to 1..100 (default 20) and
    `offset` to >= 0 by FastAPI/Pydantic query validation, so a client
    cannot request an unbounded or arbitrarily large page; invalid
    values get a normal 422. The query is explicitly ordered by id so
    pagination is deterministic. The vulnerable app, by contrast,
    returns the entire table with no limit (see
    vulnerable_app/routers/admin.py).
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return (
        db.query(User)
        .order_by(User.id)
        .offset(offset)
        .limit(limit)
        .all()
    )
