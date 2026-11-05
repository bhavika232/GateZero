"""Fixtures for tests that run the real app against a real PostgreSQL test database.

Safety rails:
- The URL comes from GATEZERO_TEST_DATABASE_URL (env var or .env), never GATEZERO_DATABASE_URL.
- The database name MUST end in "_test", or the whole run aborts. These tests drop and
  truncate tables, so this guard is what keeps them away from your dev data.
- If the variable isn't set, integration tests are SKIPPED (and pytest's -ra summary says so).
"""

from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import text
from sqlalchemy.engine import make_url

from alembic import command
from alembic.config import Config
from app.config import Settings
from app.core.api_keys import generate_key
from app.db.session import build_engine, build_session_factory
from app.main import create_app
from app.models import Agent, AgentToolGrant, ApiKey
from app.tools.handlers import StrictArgs
from app.tools.registry import ToolSpec, build_default_registry
from tests.integration.helpers import TEST_MAX_REQUEST_BYTES

REPO_ROOT = Path(__file__).resolve().parents[2]
TEST_PEPPER = "integration-test-pepper-not-a-real-secret"


class _TestEnv(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GATEZERO_", env_file=REPO_ROOT / ".env", extra="ignore"
    )
    test_database_url: str | None = None


@pytest.fixture(scope="session")
def database_url() -> str:
    url = _TestEnv().test_database_url
    if not url:
        pytest.skip("GATEZERO_TEST_DATABASE_URL is not set; skipping integration tests")
    db_name = make_url(url).database or ""
    if not db_name.endswith("_test"):
        pytest.exit(f"refusing to run: test database name {db_name!r} must end with '_test'")

    # Rebuild the schema from scratch through the real migrations, so they get tested too.
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", url.replace("%", "%%"))  # ConfigParser escaping
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    return url


@pytest.fixture(scope="session")
def settings(database_url) -> Settings:
    return Settings(
        environment="test",
        database_url=database_url,
        api_key_pepper=TEST_PEPPER,
        max_request_bytes=TEST_MAX_REQUEST_BYTES,
    )


@pytest.fixture(scope="session")
def engine(settings):
    engine = build_engine(settings.database_url.get_secret_value())
    yield engine
    engine.dispose()


@pytest.fixture(autouse=True)
def clean_tables(engine):
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE audit_events, agent_tool_grants, api_keys, agents"))


@pytest.fixture
def db(engine):
    session = build_session_factory(engine)()
    yield session
    session.close()


# --- test-only tools -------------------------------------------------------------------------


class _NoArgs(StrictArgs):
    pass


@pytest.fixture
def spy_calls() -> list[str]:
    """Records every execution of the 'spy' tool, to prove whether a tool actually ran."""
    return []


@pytest.fixture
def registry(spy_calls):
    reg = build_default_registry()

    def explode(_: _NoArgs) -> str:
        raise RuntimeError("boom: FAKE-INTERNAL-DETAIL")

    def spy(_: _NoArgs) -> str:
        spy_calls.append("called")
        return "spy ran"

    reg.register(ToolSpec("explode", "Always raises (test only).", _NoArgs, explode))
    reg.register(ToolSpec("spy", "Records that it ran (test only).", _NoArgs, spy))
    return reg


@pytest.fixture
def client(settings, registry):
    app = create_app(settings=settings, registry=registry)
    with TestClient(app) as test_client:
        yield test_client


# --- helpers ---------------------------------------------------------------------------------


@pytest.fixture
def make_agent(db):
    def _make(name: str, tools: tuple[str, ...] = (), role: str = "agent", active: bool = True):
        agent = Agent(name=name, role=role, is_active=active)
        db.add(agent)
        db.flush()
        key = generate_key(TEST_PEPPER)
        db.add(ApiKey(agent_id=agent.id, key_prefix=key.prefix, key_hash=key.key_hash))
        for tool in tools:
            db.add(AgentToolGrant(agent_id=agent.id, tool_name=tool))
        db.commit()
        return SimpleNamespace(id=agent.id, key=key.plaintext, prefix=key.prefix)

    return _make
