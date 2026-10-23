"""
Orders router for the VULNERABLE app.

Exposes:
  - POST /orders              — create an order
  - GET  /orders/{order_id}   — retrieve one order (ownership enforced)

Both require a valid JWT (via get_current_user). The order owner is always
taken from the authenticated user, and the line total is always computed
server-side — so neither owner spoofing nor client-dictated totals are
possible here.

The ONE intentional weakness in this stage lives on POST /orders: the
request schema (vulnerable_app/schemas.py: OrderCreate) puts no bounds on
quantity or unit_price, so invalid business-rule inputs (e.g. a negative
quantity) are accepted and persisted. GET /orders deliberately keeps a
correct ownership check so this stage does not re-introduce a BOLA flaw.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from vulnerable_app.auth import get_current_user
from vulnerable_app.database import get_db
from vulnerable_app.models import Order, User
from vulnerable_app.schemas import OrderCreate, OrderOut

router = APIRouter()


@router.post("/orders", response_model=OrderOut, status_code=status.HTTP_201_CREATED)
def create_order(
    order: OrderCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Create an order for the authenticated user.

    VULNERABILITY (intentional — Improper Input Validation, CWE-20 /
    CWE-1284): `order.quantity` and `order.unit_price` are used directly to
    compute the total with no check that they are positive. A request with
    quantity=-5 is accepted and a negative amount is persisted. The owner is
    taken from current_user (never the client) and the total is computed
    server-side, so the ONLY flaw demonstrated here is the missing validation
    of the quantity/price inputs.
    """
    total = order.quantity * order.unit_price  # no validation of the inputs
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
    Retrieve a single order.

    Ownership is enforced (owner-or-admin), exactly like the secure users
    endpoint — this router does NOT re-introduce a BOLA flaw. The only
    intentional weakness in this stage is input validation on POST /orders.
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
