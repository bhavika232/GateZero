"""Engine and session factory.

We use synchronous SQLAlchemy. FastAPI runs plain `def` routes and dependencies in a
threadpool, so blocking DB calls don't stall the event loop, and the code stays easy to read.
"""

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker


def build_engine(database_url: str) -> Engine:
    return create_engine(
        database_url,
        pool_pre_ping=True,  # transparently replace connections the DB has dropped
        # Never echo bound parameter values into exception messages or logs.
        # Audit rows can contain security findings we don't want copied into app logs.
        hide_parameters=True,
    )


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    # expire_on_commit=False lets us read attributes after commit without a new round trip.
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
