"""
Database setup for the VULNERABLE app.

This module wires up SQLAlchemy 2.x to a local SQLite file. It is
intentionally simple: one engine, one session factory, one declarative
Base that all models inherit from, and a FastAPI dependency that hands
out a database session per request and closes it afterwards.

Nothing in this file is a "vulnerability" on its own — it's just plumbing
shared by every endpoint.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# SQLite file lives next to this module, inside vulnerable_app/.
# "check_same_thread=False" is required because FastAPI can use the same
# connection across different threads within a single request lifecycle.
DATABASE_URL = "sqlite:///./vulnerable_app/vulnerable.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)

# SessionLocal is a factory: calling SessionLocal() gives us a new
# database session. We don't share one global session across requests.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base is the class every ORM model (User, Order, ...) will inherit from.
# SQLAlchemy uses this to know which classes map to database tables.
Base = declarative_base()


def get_db():
    """
    FastAPI dependency that provides a database session to a path
    function and guarantees it gets closed afterwards, even if the
    request raises an error.

    Usage in an endpoint:
        def some_endpoint(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
