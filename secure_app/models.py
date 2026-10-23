"""
SQLAlchemy ORM models for the SECURE app.

Same shape as vulnerable_app/models.py at this stage — the schema itself
isn't what makes the vulnerable app insecure or the secure app safe.
The difference will come later, in how endpoints validate input and
enforce authorization.
"""

from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, Float, ForeignKey, DateTime
from sqlalchemy.orm import relationship

from secure_app.database import Base


def _utcnow() -> datetime:
    """Naive UTC timestamp (avoids the deprecated datetime.utcnow())."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    """A registered user of the demo app."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)

    # We never store plaintext passwords — only the hashed value.
    password_hash = Column(String, nullable=False)

    # "user" or "admin". A plain string is enough for this demo lab.
    role = Column(String, nullable=False, default="user")

    # --- Account-lockout state (Stage 6; secure app only) -------------
    # Consecutive failed-password attempts since the last success, and
    # the timestamp (naive UTC) until which the account is temporarily
    # locked. These back the per-account lockout in auth.py; the
    # vulnerable app has no equivalent.
    failed_login_attempts = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime, nullable=True)

    orders = relationship("Order", back_populates="owner")


class Order(Base):
    """An order placed by a user."""

    __tablename__ = "orders"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    product = Column(String, nullable=False)
    quantity = Column(Integer, nullable=False)
    unit_price = Column(Float, nullable=False)

    # Server-calculated line total (quantity * unit_price) — never taken
    # directly from the client.
    amount = Column(Float, nullable=False)

    # e.g. "pending", "paid", "shipped"
    status = Column(String, nullable=False, default="pending")

    created_at = Column(DateTime, nullable=False, default=_utcnow)

    owner = relationship("User", back_populates="orders")
