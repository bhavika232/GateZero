"""The tool-call lifecycle, in one readable function.

Each numbered step matches the README. Steps marked TODO are later phases; they are listed
here so the order of checks is fixed now and nobody slots a check in the wrong place.

  1. (route)  authenticate the caller             -> app/api/deps.py
  2. (route)  read the body with a hard size cap  -> app/api/deps.py
  3. reject oversized bodies
  4. parse and validate the request envelope
  5. look up the tool and apply default-deny authorization
  6. validate arguments against the tool's schema
  7. TODO step 5: tool-specific checks (path containment)
  8. TODO step 6: scan arguments for secrets
  9. TODO step 7: rate limits (per-agent check will move up to right after authentication)
 10. AUDIT PHASE 1: record "allow / pending"  -> if this fails, STOP (fail closed)
 11. execute the registered handler
 12. TODO step 8: scan output for prompt injection
 13. AUDIT PHASE 2: record the outcome
 14. return the structured response
"""

import logging
import time
import uuid
from typing import Any, NoReturn

from pydantic import ValidationError

from app.core.argument_validator import (
    ArgumentValidationError,
    sanitize_validation_errors,
    validate_arguments,
)
from app.core.audit_service import AuditRecord, AuditService, AuditWriteError
from app.core.auth import AuthenticatedAgent
from app.core.errors import Decision, GatewayError, Outcome, ReasonCode, Stage
from app.core.policy_engine import authorize_tool
from app.core.request_body import RawBody
from app.schemas.tool_call import ToolCallRequest, ToolCallResponse
from app.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

MAX_LOC_PART_CHARS = 64


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


def _audit_findings(details: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep only where and what kind of error, truncated. Field names are caller-chosen text."""
    return [
        {
            "type": "validation_error",
            "error_type": d["type"],
            "loc": [part[:MAX_LOC_PART_CHARS] for part in d["loc"]],
        }
        for d in details
    ]


class GatewayService:
    def __init__(self, registry: ToolRegistry, audit: AuditService) -> None:
        self._registry = registry
        self._audit = audit

    def handle(
        self, agent: AuthenticatedAgent, body: RawBody, request_id: uuid.UUID
    ) -> ToolCallResponse:
        started = time.perf_counter()

        # 3. Size
        if body.too_large:
            self._deny(
                agent, request_id, started,
                stage=Stage.REQUEST, reason=ReasonCode.REQUEST_TOO_LARGE,
                status_code=413, message="Request body exceeds the configured size limit.",
            )

        # 4. Envelope. model_validate_json parses and validates in one step, so invalid JSON,
        #    wrong types and unexpected top-level fields (e.g. a spoofed "agent_id") all fail here.
        try:
            request = ToolCallRequest.model_validate_json(body.data)
        except ValidationError as exc:
            details = sanitize_validation_errors(exc)
            self._deny(
                agent, request_id, started,
                stage=Stage.REQUEST, reason=ReasonCode.REQUEST_MALFORMED,
                status_code=400, message="Request body is not a valid tool call.",
                details=details, findings=_audit_findings(details),
            )

        # 5. Default-deny authorization
        decision = authorize_tool(request.tool, self._registry.names(), agent.granted_tools)
        if not decision.allowed:
            self._deny(
                agent, request_id, started,
                stage=Stage.POLICY, reason=decision.reason_code, tool_name=request.tool,
                # Same public answer for "unknown" and "not permitted" (see policy_engine.py).
                public_code=ReasonCode.TOOL_NOT_PERMITTED,
                status_code=403, message="This agent is not permitted to call that tool.",
            )
        spec = self._registry.get(request.tool)
        if spec is None:  # unreachable: authorize_tool already checked registration
            raise RuntimeError("registry changed during request")

        # 6. Arguments
        try:
            args = validate_arguments(spec, request.arguments)
        except ArgumentValidationError as exc:
            self._deny(
                agent, request_id, started,
                stage=Stage.POLICY, reason=ReasonCode.ARGS_INVALID, tool_name=spec.name,
                status_code=422, message="Tool arguments failed validation.",
                details=exc.details, findings=_audit_findings(exc.details),
            )

        # 7–9. TODO (later phases): path containment, secret scan, rate limits.

        # 10. Audit phase 1 — fail closed.
        try:
            event_id = self._audit.record(
                AuditRecord(
                    request_id=request_id,
                    agent_id=agent.id,
                    tool_name=spec.name,
                    stage=Stage.EXECUTION,
                    decision=Decision.ALLOW,
                    outcome=Outcome.PENDING,
                    reason_code=ReasonCode.ALLOWED,
                )
            )
        except AuditWriteError:
            raise GatewayError(
                503, ReasonCode.AUDIT_UNAVAILABLE,
                "The call was not executed because it could not be audited. Try again later.",
            ) from None

        # 11. Execute
        try:
            output = spec.handler(args)
            if not isinstance(output, str):
                raise TypeError("tool handlers must return str")
        except Exception as exc:
            # Log the exception class only; its message might echo argument values.
            logger.error("tool %s failed: %s", spec.name, type(exc).__name__)
            self._finalize(
                event_id, started,
                outcome=Outcome.EXECUTION_ERROR, reason=ReasonCode.TOOL_EXECUTION_FAILED,
            )
            raise GatewayError(
                502, ReasonCode.TOOL_EXECUTION_FAILED, "The tool failed to execute."
            ) from None

        # 12. TODO (later phase): prompt-injection scan of `output`.

        # 13. Audit phase 2
        self._finalize(event_id, started, outcome=Outcome.EXECUTED, reason=ReasonCode.ALLOWED)

        # 14. Respond
        return ToolCallResponse(
            request_id=request_id,
            audit_event_id=event_id,
            tool=spec.name,
            status="executed",
            output=output,
        )

    # --- helpers ---------------------------------------------------------------------------

    def _deny(
        self,
        agent: AuthenticatedAgent,
        request_id: uuid.UUID,
        started: float,
        *,
        stage: Stage,
        reason: ReasonCode,
        status_code: int,
        message: str,
        tool_name: str | None = None,
        public_code: ReasonCode | None = None,
        details: list[dict[str, Any]] | None = None,
        findings: list[dict[str, Any]] | None = None,
    ) -> NoReturn:
        """Record a pre-execution denial, then refuse. Never returns."""
        try:
            self._audit.record(
                AuditRecord(
                    request_id=request_id,
                    agent_id=agent.id,
                    tool_name=tool_name,
                    stage=stage,
                    decision=Decision.DENY,
                    outcome=Outcome.DENIED,
                    reason_code=reason,
                    findings=findings or [],
                    duration_ms=_elapsed_ms(started),
                )
            )
        except AuditWriteError:
            # Already logged by AuditService. The request is denied either way.
            pass
        raise GatewayError(status_code, public_code or reason, message, details=details)

    def _finalize(
        self, event_id: uuid.UUID, started: float, *, outcome: Outcome, reason: ReasonCode
    ) -> None:
        try:
            self._audit.finalize(
                event_id,
                stage=Stage.EXECUTION,
                outcome=outcome,
                reason_code=reason,
                duration_ms=_elapsed_ms(started),
            )
        except AuditWriteError:
            # The tool already ran, so we can't undo it. The row stays 'pending', which an
            # operator can query for. Already logged by AuditService.
            pass
