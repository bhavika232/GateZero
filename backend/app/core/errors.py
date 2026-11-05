"""Shared vocabulary for security decisions: reason codes, stages, outcomes, and the
exception the gateway raises when it refuses a request.

Keeping these in one module means the policy engine, the audit log, the API responses and the
tests all agree on the exact same strings. The database CHECK constraints are generated from
these enums too, so an unknown value can't be written to the audit table.

This module has no FastAPI or SQLAlchemy imports on purpose, so the security logic that
uses it can be unit-tested in isolation.
"""

from enum import StrEnum
from typing import Any


class Stage(StrEnum):
    """Where in the request lifecycle a decision was made."""

    AUTH = "auth"
    REQUEST = "request"
    POLICY = "policy"
    EXECUTION = "execution"
    OUTPUT = "output"


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class Outcome(StrEnum):
    """What finally happened. PENDING exists only between the two phases of an allowed call."""

    PENDING = "pending"
    EXECUTED = "executed"
    DENIED = "denied"  # blocked before the tool ran
    EXECUTION_ERROR = "execution_error"
    OUTPUT_BLOCKED = "output_blocked"  # tool ran, output withheld (injection detector, later)


class ReasonCode(StrEnum):
    ALLOWED = "ALLOWED"

    # Authentication
    AUTH_MISSING = "AUTH_MISSING"
    AUTH_INVALID = "AUTH_INVALID"
    AUTH_REVOKED = "AUTH_REVOKED"
    AUTH_AGENT_INACTIVE = "AUTH_AGENT_INACTIVE"
    AUTH_WRONG_ROLE = "AUTH_WRONG_ROLE"

    # Request structure
    REQUEST_TOO_LARGE = "REQUEST_TOO_LARGE"
    REQUEST_MALFORMED = "REQUEST_MALFORMED"

    # Authorization
    TOOL_UNKNOWN = "TOOL_UNKNOWN"
    TOOL_NOT_PERMITTED = "TOOL_NOT_PERMITTED"

    # Arguments
    ARGS_INVALID = "ARGS_INVALID"

    # Execution
    TOOL_EXECUTION_FAILED = "TOOL_EXECUTION_FAILED"

    # Infrastructure
    AUDIT_UNAVAILABLE = "AUDIT_UNAVAILABLE"


class GatewayError(Exception):
    """Raised to refuse a request. The API layer turns it into a structured error response.

    `public_code` is what the caller sees. It can be deliberately less specific than the
    reason code we store in the audit log (see policy_engine.py for why).
    """

    def __init__(
        self,
        status_code: int,
        public_code: ReasonCode,
        message: str,
        details: list[dict[str, Any]] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.public_code = public_code
        self.message = message
        self.details = details
        self.headers = headers
