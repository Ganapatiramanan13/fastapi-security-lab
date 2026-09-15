"""
Database setup for the SECURE app.

Mirrors vulnerable_app/database.py in structure, but is a fully separate
implementation with its own SQLite file. Keeping the two apps completely
independent means a fix in secure_app can never accidentally "leak" into
vulnerable_app and mask the vulnerability we're trying to demonstrate.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Separate database file from vulnerable_app — the two apps never share data.
DATABASE_URL = "sqlite:///./secure_app/secure.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """
    FastAPI dependency that provides a database session to a path
    function and guarantees it gets closed afterwards, even if the
    request raises an error.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
