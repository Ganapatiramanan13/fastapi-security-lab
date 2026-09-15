"""
SQLAlchemy ORM models for the SECURE app.

Same shape as vulnerable_app/models.py at this stage — the schema itself
isn't what makes the vulnerable app insecure or the secure app safe.
The difference will come later, in how endpoints validate input and
enforce authorization.
"""

from sqlalchemy import Column, Integer, String, Float, ForeignKey
from sqlalchemy.orm import relationship

from secure_app.database import Base


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

    orders = relationship("Order", back_populates="owner")


class Order(Base):
    """An order placed by a user."""

    __tablename__ = "orders"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    product = Column(String, nullable=False)
    amount = Column(Float, nullable=False)

    # e.g. "pending", "paid", "shipped"
    status = Column(String, nullable=False, default="pending")

    owner = relationship("User", back_populates="orders")
