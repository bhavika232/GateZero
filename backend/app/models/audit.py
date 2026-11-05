"""The audit log table.

Design notes:
- Enum-like columns are VARCHAR + CHECK constraints rather than native PostgreSQL ENUM types.
  Adding a new reason code later is then a one-line constraint change instead of an
  ALTER TYPE dance.
- `findings` is JSONB and must only ever contain redacted data (no secrets, no raw arguments).
- `agent_id` is NULL when no trusted identity exists, e.g. failed authentication.
- `completed_at` / `duration_ms` are filled in by the second phase of an allowed call.
  A row stuck in outcome='pending' means the tool may have run but the result wasn't
  recorded — something an operator should investigate.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.errors import Decision, Outcome, ReasonCode, Stage
from app.db.base import Base


def _in_check(column: str, enum_cls: type) -> str:
    values = ", ".join(f"'{member.value}'" for member in enum_cls)
    return f"{column} IN ({values})"


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        CheckConstraint(_in_check("stage", Stage), name="stage_valid"),
        CheckConstraint(_in_check("decision", Decision), name="decision_valid"),
        CheckConstraint(_in_check("outcome", Outcome), name="outcome_valid"),
        CheckConstraint(_in_check("reason_code", ReasonCode), name="reason_code_valid"),
        CheckConstraint("duration_ms IS NULL OR duration_ms >= 0", name="duration_non_negative"),
        # A deny can never be recorded as having executed, and vice versa.
        CheckConstraint(
            "(decision = 'deny' AND outcome = 'denied') OR "
            "(decision = 'allow' AND outcome <> 'denied')",
            name="decision_outcome_consistent",
        ),
        Index("ix_audit_events_agent_created", "agent_id", text("created_at DESC")),
        Index("ix_audit_events_outcome_created", "outcome", text("created_at DESC")),
        Index("ix_audit_events_request_id", "request_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    request_id: Mapped[uuid.UUID]
    agent_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("agents.id"))
    tool_name: Mapped[str | None] = mapped_column(String(64))
    stage: Mapped[str] = mapped_column(String(20))
    decision: Mapped[str] = mapped_column(String(10))
    outcome: Mapped[str] = mapped_column(String(20))
    reason_code: Mapped[str] = mapped_column(String(50))
    findings: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, server_default=text("'[]'::jsonb")
    )
    duration_ms: Mapped[int | None] = mapped_column(Integer)
