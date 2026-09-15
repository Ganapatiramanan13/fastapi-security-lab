"""
SQLAlchemy ORM models for the VULNERABLE app.

These define the shape of our two database tables: users and orders.
The models themselves are not vulnerable — vulnerabilities will be
introduced later in how the *endpoints* use these models (e.g. trusting
client input, skipping ownership checks), not in the schema itself.
"""

from sqlalchemy import Column, Integer, String, Float, ForeignKey
from sqlalchemy.orm import relationship

from vulnerable_app.database import Base


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

    # One user can have many orders.
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
