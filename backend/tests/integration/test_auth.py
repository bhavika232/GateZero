"""Authentication: who can reach the gateway, and what gets audited when they can't."""

from datetime import UTC, datetime

from sqlalchemy import select

from app.models import Agent, ApiKey
from tests.integration.helpers import bearer, dumps, only_event

ECHO = {"tool": "echo", "arguments": {"text": "hi"}}


def test_missing_key_is_rejected_and_audited(client, db):
    response = client.post("/v1/tool-calls", json=ECHO)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTH_MISSING"
    assert response.headers["WWW-Authenticate"] == "Bearer"

    event = only_event(db, response)
    assert event.stage == "auth"
    assert event.decision == "deny"
    assert event.reason_code == "AUTH_MISSING"
    assert event.agent_id is None  # no trusted identity exists


def test_non_bearer_scheme_is_treated_as_missing(client):
    response = client.post("/v1/tool-calls", json=ECHO, headers={"Authorization": "Basic abc"})
    assert response.status_code == 401


def test_garbage_key_is_rejected(client, db):
    response = client.post("/v1/tool-calls", json=ECHO, headers=bearer("not-a-key"))
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTH_INVALID"
    assert only_event(db, response).reason_code == "AUTH_INVALID"


def test_right_prefix_wrong_secret_is_rejected_without_storing_the_key(client, db, make_agent):
    agent = make_agent("alpha", tools=("echo",))
    forged = f"gz_{agent.prefix}_" + "A" * 43

    response = client.post("/v1/tool-calls", json=ECHO, headers=bearer(forged))
    assert response.status_code == 401

    event = only_event(db, response)
    assert event.reason_code == "AUTH_INVALID"
    assert event.agent_id is None  # a wrong secret proves nothing about identity
    assert event.findings[0]["type"] == "key_prefix_fingerprint"
    stored = dumps(event)
    assert forged not in stored
    assert agent.prefix not in stored


def test_revoked_key_is_rejected_but_caller_is_not_told_why(client, db, make_agent):
    agent = make_agent("alpha", tools=("echo",))
    key_row = db.scalar(select(ApiKey).where(ApiKey.key_prefix == agent.prefix))
    key_row.revoked_at = datetime.now(UTC)
    db.commit()

    response = client.post("/v1/tool-calls", json=ECHO, headers=bearer(agent.key))
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTH_INVALID"
    assert only_event(db, response).reason_code == "AUTH_REVOKED"


def test_disabled_agent_is_rejected(client, db, make_agent):
    agent = make_agent("alpha", tools=("echo",))
    db.get(Agent, agent.id).is_active = False
    db.commit()

    response = client.post("/v1/tool-calls", json=ECHO, headers=bearer(agent.key))
    assert response.status_code == 401
    event = only_event(db, response)
    assert event.reason_code == "AUTH_AGENT_INACTIVE"
    assert event.agent_id == agent.id  # key was valid, so identity is trusted


def test_auditor_identity_cannot_call_tools(client, db, make_agent):
    auditor = make_agent("watcher", role="auditor")
    response = client.post("/v1/tool-calls", json=ECHO, headers=bearer(auditor.key))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "AUTH_WRONG_ROLE"
    assert only_event(db, response).agent_id == auditor.id


def test_unauthenticated_oversized_body_gets_401_not_413(client):
    """Authentication runs before the body is read."""
    response = client.post("/v1/tool-calls", content=b"x" * 50_000)
    assert response.status_code == 401


def test_plaintext_keys_are_never_stored(db, make_agent):
    agent = make_agent("alpha")
    row = db.scalar(select(ApiKey).where(ApiKey.agent_id == agent.id))
    assert agent.key not in (row.key_hash, row.key_prefix)
    assert agent.key.split("_", 2)[2] not in row.key_hash
