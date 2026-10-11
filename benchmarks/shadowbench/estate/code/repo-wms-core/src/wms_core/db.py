"""Engine and session helpers."""

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

_session_factory: sessionmaker | None = None


def init_engine(database_url: str) -> None:
    global _session_factory
    engine = create_engine(database_url, pool_pre_ping=True)
    _session_factory = sessionmaker(bind=engine)


def session() -> Session:
    if _session_factory is None:
        raise RuntimeError("init_engine() has not been called")
    return _session_factory()
