"""Alembic environment: tells Alembic which database to talk to and which models exist.

The URL comes from (in order):
1. an explicit `sqlalchemy.url` set programmatically (the test suite does this), or
2. GATEZERO_DATABASE_URL via app settings (normal development use).
"""

from logging.config import fileConfig

from sqlalchemy import create_engine, pool

from alembic import context
from app.db.base import Base
from app.models import AuditEvent  # noqa: F401  (import registers all models on Base.metadata)

config = context.config

if config.config_file_name is not None:
    # disable_existing_loggers=False: don't silence the app's loggers when run from tests.
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def _database_url() -> str:
    explicit = config.get_main_option("sqlalchemy.url")
    if explicit:
        return explicit
    from app.config import get_settings

    return get_settings().database_url.get_secret_value()


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of executing it (`alembic upgrade head --sql`)."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    # NullPool: a migration is a one-off process, so don't keep connections open afterwards.
    engine = create_engine(_database_url(), poolclass=pool.NullPool, hide_parameters=True)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
