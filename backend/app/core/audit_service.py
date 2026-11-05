"""Audit persistence. The only module that writes to audit_events.

When is an audit record created? (also documented in the README)
- Failed authentication ............ one row, stage=auth, agent_id NULL (no trusted identity)
- Authenticated but rejected ....... one row, decision=deny, outcome=denied, written BEFORE
  (too large, malformed, unknown      the error response is returned
  tool, not permitted, bad args)
- Allowed call ..................... TWO phases on the same row:
    1. insert decision=allow, outcome=pending   -> must succeed, or the tool does not run
    2. update outcome=executed | execution_error, completed_at, duration_ms

Fail-closed rule: if phase 1 fails, the gateway refuses with 503 and never executes the tool.
If a deny can't be written, the request is still denied (logging failure never flips a decision).

What is never stored: API keys, request bodies, raw tool arguments, raw tool output.
"""

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.errors import Decision, Outcome, ReasonCode, Stage
from app.models.audit import AuditEvent

logger = logging.getLogger(__name__)


class AuditWriteError(Exception):
    """The audit record could not be persisted."""


@dataclass
class AuditRecord:
    request_id: uuid.UUID
    stage: Stage
    decision: Decision
    outcome: Outcome
    reason_code: ReasonCode
    agent_id: uuid.UUID | None = None
    tool_name: str | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    duration_ms: int | None = None


class AuditService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def record(self, record: AuditRecord) -> uuid.UUID:
        """Insert and COMMIT one audit row. Raises AuditWriteError on any DB failure."""
        event = AuditEvent(
            id=uuid.uuid4(),
            request_id=record.request_id,
            agent_id=record.agent_id,
            tool_name=record.tool_name,
            stage=record.stage.value,
            decision=record.decision.value,
            outcome=record.outcome.value,
            reason_code=record.reason_code.value,
            findings=record.findings,
            duration_ms=record.duration_ms,
        )
        try:
            self._session.add(event)
            self._session.commit()
        except SQLAlchemyError as exc:
            self._session.rollback()
            # Log the exception type only; hide_parameters=True keeps values out of the message.
            logger.error("audit insert failed: %s", type(exc).__name__)
            raise AuditWriteError from exc
        return event.id

    def finalize(
        self,
        event_id: uuid.UUID,
        *,
        stage: Stage,
        outcome: Outcome,
        reason_code: ReasonCode,
        duration_ms: int,
        findings: list[dict[str, Any]] | None = None,
    ) -> None:
        """Phase 2 of an allowed call: record what actually happened."""
        values: dict[str, Any] = {
            "stage": stage.value,
            "outcome": outcome.value,
            "reason_code": reason_code.value,
            "duration_ms": duration_ms,
            "completed_at": func.now(),
        }
        if findings is not None:
            values["findings"] = findings
        try:
            self._session.execute(
                update(AuditEvent)
                .where(AuditEvent.id == event_id, AuditEvent.outcome == Outcome.PENDING.value)
                .values(**values)
            )
            self._session.commit()
        except SQLAlchemyError as exc:
            self._session.rollback()
            logger.error("audit finalize failed for event %s: %s", event_id, type(exc).__name__)
            raise AuditWriteError from exc
