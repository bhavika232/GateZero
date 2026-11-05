"""The database itself refuses inconsistent audit rows, even if application code had a bug."""

import uuid

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError


def test_migrations_created_all_tables(engine):
    tables = set(inspect(engine).get_table_names())
    assert {"agents", "api_keys", "agent_tool_grants", "audit_events"} <= tables


def _insert_audit(engine, decision: str, outcome: str, reason: str = "ALLOWED") -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_events (id, request_id, stage, decision, outcome, reason_code) "
                "VALUES (:id, :rid, 'policy', :decision, :outcome, :reason)"
            ),
            {"id": uuid.uuid4(), "rid": uuid.uuid4(), "decision": decision,
             "outcome": outcome, "reason": reason},
        )


def test_valid_row_is_accepted(engine):
    _insert_audit(engine, "deny", "denied", "TOOL_UNKNOWN")


@pytest.mark.parametrize(
    ("decision", "outcome", "reason"),
    [
        ("deny", "executed", "TOOL_UNKNOWN"),  # a denied call can't have executed
        ("allow", "denied", "ALLOWED"),
        ("maybe", "denied", "ALLOWED"),  # unknown decision
        ("deny", "denied", "MADE_UP_REASON"),  # unknown reason code
    ],
)
def test_inconsistent_rows_are_rejected(engine, decision, outcome, reason):
    with pytest.raises(IntegrityError):
        _insert_audit(engine, decision, outcome, reason)
