"""Engine and session management.

Transaction convention used throughout the project: service functions receive
a ``Session`` and only ``flush()``; the caller decides when to commit, normally
by wrapping one user action in :func:`session_scope`. This keeps each user
action atomic and lets tests roll everything back.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, event, inspect
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from phishsense import config
from phishsense.data.models import Base

IN_MEMORY_URL = "sqlite://"


def create_db_engine(url: str | None = None) -> Engine:
    """Create an engine for ``url`` (default: the application's SQLite file).

    SQLite does not enforce foreign keys unless asked, so every new connection
    turns them on.
    """
    if url is None:
        config.DATA_DIR.mkdir(parents=True, exist_ok=True)
        url = f"sqlite:///{config.DB_PATH}"

    if url == IN_MEMORY_URL:
        # One shared connection, otherwise each connection gets its own empty DB.
        engine = create_engine(
            url, connect_args={"check_same_thread": False}, poolclass=StaticPool
        )
    else:
        # File databases: SQLAlchemy 2 uses a QueuePool and sets
        # check_same_thread=False itself, so the GUI's worker thread can open
        # its own session (verified; each thread uses its own Session).
        engine = create_engine(url)

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine


class SchemaError(RuntimeError):
    """The existing database cannot be upgraded automatically."""


def _add_missing_columns(engine: Engine) -> list[str]:
    """Minimal forward migration for SQLite.

    ``create_all`` creates missing tables but never alters existing ones. When a
    release adds a column, existing databases need ``ALTER TABLE ... ADD
    COLUMN``. Only columns that are nullable or have a server default can be
    added safely; anything else raises :class:`SchemaError` instead of guessing.
    Returns the columns that were added.
    """
    inspector = inspect(engine)
    added = []
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if not inspector.has_table(table.name):
                continue
            existing = {c["name"] for c in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in existing:
                    continue
                if not column.nullable and column.server_default is None:
                    raise SchemaError(
                        f"Database column {table.name}.{column.name} is missing and cannot be "
                        "added automatically. Back up and recreate the database with "
                        "'python -m phishsense.data.seed --reset'."
                    )
                ddl = f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" ' \
                      f"{column.type.compile(engine.dialect)}"
                if column.server_default is not None:
                    ddl += f" NOT NULL DEFAULT {column.server_default.arg.text}" \
                        if not column.nullable else f" DEFAULT {column.server_default.arg.text}"
                conn.exec_driver_sql(ddl)
                added.append(f"{table.name}.{column.name}")
    return added


def init_db(engine: Engine) -> list[str]:
    """Create missing tables and add missing columns. Returns added columns."""
    Base.metadata.create_all(engine)
    return _add_missing_columns(engine)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    # expire_on_commit=False: the UI keeps using ORM objects after a commit.
    return sessionmaker(bind=engine, expire_on_commit=False)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """One unit of work: commit on success, roll back on any exception."""
    session = factory()
    try:
        yield session
        session.commit()
    except BaseException:
        session.rollback()
        raise
    finally:
        session.close()
