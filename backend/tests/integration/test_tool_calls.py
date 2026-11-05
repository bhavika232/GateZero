"""The full tool-call lifecycle against the real app and a real database."""

import json
import uuid

import pytest

from app.core.audit_service import AuditService, AuditWriteError
from tests.integration.helpers import (
    TEST_MAX_REQUEST_BYTES,
    audit_events_for,
    bearer,
    dumps,
    only_event,
)


def call(client, key, tool, arguments=None, **extra):
    body = {"tool": tool, "arguments": arguments or {}, **extra}
    return client.post("/v1/tool-calls", json=body, headers=bearer(key))


# --- the vertical slice ----------------------------------------------------------------------


def test_authorized_call_executes_and_is_audited(client, db, make_agent):
    agent = make_agent("alpha", tools=("echo",))

    response = call(client, agent.key, "echo", {"text": "hello gateway"})

    assert response.status_code == 200
    body = response.json()
    assert body["output"] == "hello gateway"
    assert body["status"] == "executed"
    assert body["request_id"] == response.headers["X-Request-ID"]

    event = only_event(db, response)
    assert event.id == uuid.UUID(body["audit_event_id"])
    assert event.agent_id == agent.id
    assert event.tool_name == "echo"
    assert (event.decision, event.outcome, event.reason_code) == ("allow", "executed", "ALLOWED")
    assert event.completed_at is not None
    assert event.duration_ms is not None and event.duration_ms >= 0
    # Arguments and output are not copied into the audit log.
    assert "hello gateway" not in dumps(event)


# --- authorization ---------------------------------------------------------------------------


def test_unknown_tool_is_denied_without_revealing_it_is_unknown(client, db, make_agent):
    agent = make_agent("alpha", tools=("echo",))

    response = call(client, agent.key, "delete_everything")

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "TOOL_NOT_PERMITTED"
    event = only_event(db, response)
    assert (event.decision, event.outcome) == ("deny", "denied")
    assert event.reason_code == "TOOL_UNKNOWN"  # precise reason is for operators only


def test_tool_not_on_allowlist_is_denied(client, db, make_agent, spy_calls):
    agent = make_agent("alpha", tools=("echo",))

    response = call(client, agent.key, "spy")

    assert response.status_code == 403
    assert spy_calls == []  # the tool never ran
    event = only_event(db, response)
    assert event.reason_code == "TOOL_NOT_PERMITTED"
    assert event.tool_name == "spy"


def test_spoofed_agent_id_in_body_is_rejected(client, db, make_agent):
    caller = make_agent("alpha", tools=("echo",))
    victim = make_agent("beta", tools=("echo", "word_count"))

    response = call(client, caller.key, "word_count", {"text": "a b"}, agent_id=str(victim.id))

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "REQUEST_MALFORMED"
    assert only_event(db, response).agent_id == caller.id  # identity came from the key


# --- request and argument validation ---------------------------------------------------------


def test_malformed_json_is_rejected_and_audited(client, db, make_agent):
    agent = make_agent("alpha", tools=("echo",))
    response = client.post(
        "/v1/tool-calls",
        content=b'{"tool": "echo", ',
        headers={**bearer(agent.key), "Content-Type": "application/json"},
    )
    assert response.status_code == 400
    event = only_event(db, response)
    assert (event.stage, event.reason_code) == ("request", "REQUEST_MALFORMED")


@pytest.mark.parametrize(
    "arguments",
    [{}, {"text": 123}, {"text": ""}, {"text": "ok", "path": "../../etc/passwd"}],
)
def test_invalid_arguments_are_rejected_and_audited(client, db, make_agent, arguments):
    agent = make_agent("alpha", tools=("echo",))
    response = call(client, agent.key, "echo", arguments)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "ARGS_INVALID"
    assert only_event(db, response).reason_code == "ARGS_INVALID"


def test_rejected_argument_values_are_not_echoed_or_stored(client, db, make_agent):
    agent = make_agent("alpha", tools=("echo",))
    fake_secret = "FAKE-TOKEN-for-tests-0123456789"

    response = call(client, agent.key, "echo", {"text": [fake_secret]})

    assert response.status_code == 422
    assert fake_secret not in response.text
    assert fake_secret not in dumps(only_event(db, response))


def test_oversized_body_is_rejected_and_audited(client, db, make_agent):
    agent = make_agent("alpha", tools=("echo",))
    response = call(client, agent.key, "echo", {"text": "x" * (TEST_MAX_REQUEST_BYTES + 1)})
    assert response.status_code == 413
    assert only_event(db, response).reason_code == "REQUEST_TOO_LARGE"


def test_oversized_body_without_content_length_is_rejected(client, db, make_agent):
    """A chunked upload has no Content-Length, so the streaming byte count must catch it."""
    agent = make_agent("alpha", tools=("echo",))
    payload = json.dumps({"tool": "echo", "arguments": {"text": "x" * 5000}}).encode()

    def chunks():
        for i in range(0, len(payload), 512):
            yield payload[i : i + 512]

    response = client.post(
        "/v1/tool-calls",
        content=chunks(),
        headers={**bearer(agent.key), "Content-Type": "application/json"},
    )
    assert response.status_code == 413


# --- execution and audit failures ------------------------------------------------------------


def test_tool_execution_error_is_audited_without_leaking_details(client, db, make_agent):
    agent = make_agent("alpha", tools=("explode",))

    response = call(client, agent.key, "explode")

    assert response.status_code == 502
    assert response.json()["error"]["code"] == "TOOL_EXECUTION_FAILED"
    assert "FAKE-INTERNAL-DETAIL" not in response.text
    event = only_event(db, response)
    assert (event.decision, event.outcome) == ("allow", "execution_error")
    assert event.reason_code == "TOOL_EXECUTION_FAILED"
    assert event.completed_at is not None


def test_audit_outage_blocks_execution(client, db, make_agent, spy_calls, monkeypatch):
    """Fail closed: if the 'allow' decision can't be recorded, the tool must not run."""
    agent = make_agent("alpha", tools=("spy",))

    def broken_record(self, record):
        raise AuditWriteError

    monkeypatch.setattr(AuditService, "record", broken_record)
    response = call(client, agent.key, "spy")

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "AUDIT_UNAVAILABLE"
    assert spy_calls == []
    assert audit_events_for(db, response) == []


def test_audit_outage_never_turns_a_deny_into_an_allow(client, make_agent, spy_calls, monkeypatch):
    agent = make_agent("alpha", tools=("echo",))  # spy NOT granted

    def broken_record(self, record):
        raise AuditWriteError

    monkeypatch.setattr(AuditService, "record", broken_record)
    response = call(client, agent.key, "spy")

    assert response.status_code == 403
    assert spy_calls == []


# --- tool listing ----------------------------------------------------------------------------


def test_tool_list_shows_only_own_grants(client, make_agent):
    alpha = make_agent("alpha", tools=("echo",))
    beta = make_agent("beta", tools=("word_count", "spy"))

    alpha_tools = client.get("/v1/tools", headers=bearer(alpha.key)).json()["tools"]
    beta_tools = client.get("/v1/tools", headers=bearer(beta.key)).json()["tools"]

    assert [t["name"] for t in alpha_tools] == ["echo"]
    assert [t["name"] for t in beta_tools] == ["spy", "word_count"]
    assert alpha_tools[0]["arguments_schema"]["additionalProperties"] is False


def test_tool_list_requires_authentication(client):
    assert client.get("/v1/tools").status_code == 401
