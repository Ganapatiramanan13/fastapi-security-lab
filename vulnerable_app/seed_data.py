"""
Seed script for the VULNERABLE app.

Populates the local SQLite database with deterministic demo data so that
exploits and tests are repeatable. Run it directly:

    python -m vulnerable_app.seed_data

Passwords are hashed with bcrypt (via passlib) before being stored —
even in the vulnerable app, we don't store plaintext passwords, since
that's not one of the vulnerabilities we're demonstrating.
"""

from passlib.context import CryptContext

from vulnerable_app.database import Base, engine, SessionLocal
from vulnerable_app.models import User, Order

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
        print("Seed data inserted into vulnerable_app database:")
        print(f"  Users: {alice.username}, {bob.username}, {admin.username} (admin)")
        print(f"  Orders: {len(orders)} created")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
