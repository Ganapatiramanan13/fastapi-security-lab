"""
Users router for the VULNERABLE app.

Exposes GET /users/{user_id} and PUT /users/{user_id}. Both require a
valid JWT (via get_current_user), but each contains its own intentional
vulnerability — see the docstrings on each endpoint.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from vulnerable_app.auth import get_current_user
from vulnerable_app.database import get_db
from vulnerable_app.models import User
from vulnerable_app.schemas import UserOut, UserUpdate

router = APIRouter()


@router.get("/users/{user_id}", response_model=UserOut)
def get_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Return public info for the user with the given ID.

    VULNERABILITY (intentional — BOLA / IDOR, OWASP API1:2023):
    This endpoint checks that the caller is AUTHENTICATED (a valid JWT,
    via get_current_user) but never checks that the caller is AUTHORIZED
    to view this specific user_id — i.e. it never compares
    current_user.id to the requested user_id.

    That means any logged-in user can view ANY other user's record just
    by changing the number in the URL:
        GET /users/1   -> Alice's own data (expected)
        GET /users/2   -> Bob's data, even though the caller is Alice
                          (broken: Alice has no relationship to Bob's
                          record, but nothing stops the request)

    `current_user` is accepted as a parameter here specifically so it's
    visible that we HAVE the caller's identity available — we simply
    aren't using it to restrict access. The fix (a later stage) is to
    compare current_user.id against user_id and reject mismatches.
    """
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

    This endpoint DOES check ownership (current_user.id == user_id) —
    that part is deliberately correct, so this demo isolates Mass
    Assignment as its own vulnerability, separate from the BOLA flaw in
    GET /users/{user_id} above.

    VULNERABILITY (intentional — Mass Assignment, OWASP API6:2023):
    Once ownership is confirmed, every field present in the request
    body is applied directly to the User row with no allowlist:

        for field, value in update_data.items():
            setattr(user, field, value)

    Because UserUpdate (see schemas.py) includes "role" as a normal,
    client-writable field, Alice can send:

        PUT /users/1
        {"email": "alice_new@example.com", "role": "admin"}

    and this loop will happily set user.role = "admin" — self-granting
    admin privileges with zero extra authorization. A correct
    implementation would only ever apply an explicit allowlist of
    user-editable fields (username, email) and would set "role" only
    through a separate, privileged, admin-only code path. That fix is
    left for a later stage.
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

    # exclude_unset=True: only fields the client actually sent are applied.
    update_data = update.model_dump(exclude_unset=True)

    # VULNERABLE LOOP: no allowlist — whatever field names the client
    # sent (including "role") get written straight onto the ORM object.
    for field, value in update_data.items():
        setattr(user, field, value)

    db.commit()
    db.refresh(user)

    return user
