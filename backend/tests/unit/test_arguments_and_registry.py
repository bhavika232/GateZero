"""Unit tests for the tool registry, argument validation and the request envelope."""

import json

import pytest
from pydantic import BaseModel, ValidationError

from app.core.argument_validator import ArgumentValidationError, validate_arguments
from app.schemas.tool_call import ToolCallRequest
from app.tools.handlers import EchoArgs, echo
from app.tools.registry import ToolRegistry, ToolSpec, build_default_registry


@pytest.fixture
def registry():
    return build_default_registry()


def test_default_registry_contents(registry):
    assert registry.names() == frozenset({"echo", "word_count"})


def test_valid_echo_arguments(registry):
    args = validate_arguments(registry.get("echo"), {"text": "hello"})
    assert registry.get("echo").handler(args) == "hello"


def test_word_count(registry):
    args = validate_arguments(registry.get("word_count"), {"text": "one two  three\nfour"})
    assert registry.get("word_count").handler(args) == "4"


@pytest.mark.parametrize(
    "arguments",
    [
        {},  # missing field
        {"text": ""},  # too short
        {"text": 123},  # wrong type; strict mode means no coercion to "123"
        {"text": ["a"]},
        {"text": "a" * 1001},  # over max_length
        {"text": "ok", "path": "/etc/passwd"},  # unexpected extra field
    ],
)
def test_invalid_echo_arguments_are_rejected(registry, arguments):
    with pytest.raises(ArgumentValidationError):
        validate_arguments(registry.get("echo"), arguments)


def test_validation_errors_never_contain_the_rejected_value(registry):
    fake_secret = "FAKE-SECRET-VALUE-for-tests-only"
    with pytest.raises(ArgumentValidationError) as info:
        validate_arguments(registry.get("echo"), {"text": [fake_secret]})
    assert fake_secret not in json.dumps(info.value.details)
    assert info.value.details[0]["loc"] == ["text"]


def test_registry_rejects_duplicate_names():
    spec = ToolSpec(name="echo", description="", args_model=EchoArgs, handler=echo)
    with pytest.raises(ValueError, match="already registered"):
        ToolRegistry([spec, spec])


@pytest.mark.parametrize("bad_name", ["Echo", "1tool", "tool-name", "", "x" * 65, "../echo"])
def test_registry_rejects_bad_tool_names(bad_name):
    with pytest.raises(ValueError):
        ToolSpec(name=bad_name, description="", args_model=EchoArgs, handler=echo)


def test_registry_rejects_permissive_argument_models():
    class LooseArgs(BaseModel):  # no extra="forbid"
        text: str

    with pytest.raises(ValueError, match="extra='forbid'"):
        ToolSpec(name="loose", description="", args_model=LooseArgs, handler=echo)


# --- request envelope ------------------------------------------------------------------------


def test_envelope_accepts_valid_request():
    req = ToolCallRequest.model_validate_json('{"tool": "echo", "arguments": {"text": "hi"}}')
    assert req.tool == "echo"


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"not json",
        b"[]",
        b'{"arguments": {}}',  # missing tool
        b'{"tool": "Echo"}',  # pattern: lowercase only
        b'{"tool": "echo; rm -rf /"}',
        b'{"tool": "' + b"a" * 65 + b'"}',
        b'{"tool": "echo", "arguments": "text"}',  # arguments must be an object
        # Identity spoofing: the envelope has no agent_id field, and extras are forbidden.
        b'{"tool": "echo", "arguments": {}, "agent_id": "00000000-0000-0000-0000-000000000000"}',
    ],
)
def test_envelope_rejects_malformed_requests(raw):
    with pytest.raises(ValidationError):
        ToolCallRequest.model_validate_json(raw)
