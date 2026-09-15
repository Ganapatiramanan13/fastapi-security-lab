"""
Users router for the SECURE app.

Exposes GET /users/{user_id} and PUT /users/{user_id}. Both are the
fixed counterparts to vulnerable_app/routers/users.py — same route
shapes, with an object-level authorization check on GET and a strict
field allowlist (plus ownership check) on PUT.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from secure_app.auth import get_current_user
from secure_app.database import get_db
from secure_app.models import User
from secure_app.schemas import UserOut, UserUpdate

router = APIRouter()


@router.get("/users/{user_id}", response_model=UserOut)
def get_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Return public info for the user with the given ID.

    FIX (compare to vulnerable_app's version — BOLA / IDOR,
    OWASP API1:2023):
    The vulnerable endpoint checked authentication (valid JWT) but
    never checked authorization (does this caller have any right to
    THIS specific object?). Here we add exactly that check, using the
    identity already established by get_current_user:

      - Admins (current_user.role == "admin") may look up any user.
      - Everyone else may only look up their OWN record
        (current_user.id == user_id).
      - Any other combination is rejected with 403 Forbidden, BEFORE we
        even query for the target user — an ordinary user gets the same
        403 whether or not the target id exists, so this check can't be
        used to enumerate valid user IDs.

    404 is still returned separately, for an admin (or a user checking
    their own id) requesting an id that simply doesn't exist.
    """
    is_admin = current_user.role == "admin"
    is_self = current_user.id == user_id

    if not (is_admin or is_self):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to access this user's data",
        )

    user = db.query(User).filter(User.id == user_id).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    return user


@router.put("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    update: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Let a logged-in user update their own profile.

    FIX (compare to vulnerable_app's version — Mass Assignment,
    OWASP API6:2023). Two layers of defense, deliberately redundant:

    1. Schema-level allowlist: UserUpdate (schemas.py) only declares
       "username" and "email", and sets extra="forbid". If a client
       sends "role" (or any other unknown field) at all, FastAPI/Pydantic
       rejects the request with HTTP 422 before this function body even
       runs — the attack from Stage 8/9 never reaches application code.

    2. Explicit allowlist in the update logic itself: even though the
       schema already prevents "role" from ever appearing on `update`,
       we still only assign the two known-safe fields by name below,
       rather than looping over update.model_dump() and calling
       setattr() for whatever keys happen to be present. This is
       intentional defense in depth — the update logic itself would
       stay safe even if the schema were ever loosened by a future
       change, because it never trusts arbitrary field names from the
       request.

    Ownership is still enforced exactly as before: a normal user may
    only update their own record (current_user.id == user_id) — see
    GET /users/{user_id} above for the matching BOLA fix.
    """
    if current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only update your own profile",
        )

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Explicit allowlist — only these two fields are ever settable via
    # this endpoint, and only if the client actually provided them.
    if update.username is not None:
        user.username = update.username
    if update.email is not None:
        user.email = update.email

    db.commit()
    db.refresh(user)

    return user
