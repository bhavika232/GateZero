"""Unit tests for default-deny authorization."""

from app.core.errors import ReasonCode
from app.core.policy_engine import authorize_tool

REGISTERED = frozenset({"echo", "word_count"})


def test_granted_registered_tool_is_allowed():
    decision = authorize_tool("echo", REGISTERED, frozenset({"echo"}))
    assert decision.allowed
    assert decision.reason_code == ReasonCode.ALLOWED


def test_unknown_tool_is_denied():
    decision = authorize_tool("delete_everything", REGISTERED, frozenset({"echo"}))
    assert not decision.allowed
    assert decision.reason_code == ReasonCode.TOOL_UNKNOWN


def test_registered_but_not_granted_is_denied():
    decision = authorize_tool("word_count", REGISTERED, frozenset({"echo"}))
    assert not decision.allowed
    assert decision.reason_code == ReasonCode.TOOL_NOT_PERMITTED


def test_no_grants_means_nothing_is_allowed():
    for tool in REGISTERED:
        assert not authorize_tool(tool, REGISTERED, frozenset()).allowed


def test_stale_grant_for_unregistered_tool_is_denied():
    """A grant row alone can never make a tool exist."""
    decision = authorize_tool("old_tool", REGISTERED, frozenset({"old_tool"}))
    assert not decision.allowed
    assert decision.reason_code == ReasonCode.TOOL_UNKNOWN


def test_names_are_exact_match():
    assert not authorize_tool("Echo", REGISTERED, frozenset({"echo"})).allowed
    assert not authorize_tool("echo ", REGISTERED, frozenset({"echo"})).allowed
