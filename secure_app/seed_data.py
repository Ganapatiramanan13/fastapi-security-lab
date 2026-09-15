"""
Seed script for the SECURE app.

Populates the local SQLite database with the same deterministic demo
data as the vulnerable app, so behavior can be compared directly. Run
it directly:

    python -m secure_app.seed_data
"""

from passlib.context import CryptContext

from secure_app.database import Base, engine, SessionLocal
from secure_app.models import User, Order

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def seed():
    # Recreate tables from scratch so the seed data is always consistent.
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        alice = User(
            username="alice",
            email="alice@example.com",
            password_hash=pwd_context.hash("alice_password123"),
            role="user",
        )
        bob = User(
            username="bob",
            email="bob@example.com",
            password_hash=pwd_context.hash("bob_password123"),
            role="user",
        )
        admin = User(
            username="admin",
            email="admin@example.com",
            password_hash=pwd_context.hash("admin_password123"),
            role="admin",
        )
        db.add_all([alice, bob, admin])
        db.flush()  # assigns primary keys (alice.id, bob.id, admin.id) without committing yet

        orders = [
            Order(user_id=alice.id, product="Laptop", amount=999.99, status="paid"),
            Order(user_id=bob.id, product="Headphones", amount=49.50, status="pending"),
            Order(user_id=admin.id, product="Server Rack", amount=1500.00, status="shipped"),
        ]
        db.add_all(orders)

        db.commit()
        print("Seed data inserted into secure_app database:")
        print(f"  Users: {alice.username}, {bob.username}, {admin.username} (admin)")
        print(f"  Orders: {len(orders)} created")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
