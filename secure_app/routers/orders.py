"""
Orders router for the SECURE app.

Exposes the same route surface as vulnerable_app/routers/orders.py:
  - POST /orders              — create an order
  - GET  /orders/{order_id}   — retrieve one order (ownership enforced)

The endpoint logic is intentionally the same as the vulnerable app's: the
owner is taken from the authenticated user and the total is computed
server-side. The security difference lives entirely in the request schema
(secure_app/schemas.py: OrderCreate), which:
  - forbids unexpected fields (extra="forbid"), so a client cannot smuggle
    in a user_id/amount/total,
  - requires a positive quantity and a positive unit_price, and
  - requires a non-empty product name.

Any input that violates those rules is rejected with HTTP 422 before this
handler runs, so a bogus order (e.g. a negative total) can never be created.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from secure_app.auth import get_current_user
from secure_app.database import get_db
from secure_app.models import Order, User
from secure_app.schemas import OrderCreate, OrderOut

router = APIRouter()


@router.post("/orders", response_model=OrderOut, status_code=status.HTTP_201_CREATED)
def create_order(
    order: OrderCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Create an order for the authenticated user.

    FIX (compare to vulnerable_app — Improper Input Validation): by the time
    this function runs, OrderCreate has already enforced quantity > 0,
    unit_price > 0, a non-empty product, and no unexpected fields. The owner
    is taken from current_user and the total is computed server-side, so the
    client can neither choose the owner nor dictate the stored total.
    """
    total = order.quantity * order.unit_price  # inputs already validated
    db_order = Order(
        user_id=current_user.id,
        product=order.product,
        quantity=order.quantity,
        unit_price=order.unit_price,
        amount=total,
        status="pending",
    )
    db.add(db_order)
    db.commit()
    db.refresh(db_order)
    return db_order


@router.get("/orders/{order_id}", response_model=OrderOut)
def get_order(
    order_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Retrieve a single order. Object-level authorization: the caller must own
    the order (order.user_id == current_user.id) or be an admin; otherwise a
    403 is returned. A missing order returns 404.
    """
    order = db.query(Order).filter(Order.id == order_id).first()
    if order is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Order not found",
        )
    if current_user.role != "admin" and order.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to access this order",
        )
    return order
