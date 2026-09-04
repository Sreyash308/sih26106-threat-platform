"""
SQLite database engine and session factory with SQLAlchemy.
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./email_threat.db")

# For SQLite, check_same_thread=False is needed for multi-threaded FastAPI execution
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args, echo=False)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """Dependency for obtaining database sessions in FastAPI route handlers."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Creates database tables if they do not already exist."""
    from . import models  # noqa: F401
    Base.metadata.create_all(bind=engine)


# Initialize tables on import to ensure test client and workers have active schema
init_db()
