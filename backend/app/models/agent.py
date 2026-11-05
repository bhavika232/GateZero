"""Identity and permission tables: agents, their API keys, and their tool grants.

Note what is NOT here: a tools table. Tools are Python handlers defined in app/tools/, so the
set of executable tools is controlled by code review, not by whoever can write to the DB.
A grant row can only refer to a tool by name; the gateway re-checks the name against the
in-code registry on every call (default deny).
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

AGENT_ROLES = ("agent", "auditor")


class Agent(Base):
    __tablename__ = "agents"
    __table_args__ = (
        CheckConstraint(f"role IN {AGENT_ROLES!r}", name="role_valid"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    # "agent" may call tools; "auditor" may read the audit log (endpoint arrives in a later step).
    role: Mapped[str] = mapped_column(String(20), default="agent")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    api_keys: Mapped[list["ApiKey"]] = relationship(back_populates="agent")
    tool_grants: Mapped[list["AgentToolGrant"]] = relationship(back_populates="agent")


class ApiKey(Base):
    """One credential for one agent. The plaintext key is never stored.

    key_prefix: a short random, non-secret identifier embedded in the key, used to find the row.
    key_hash:   HMAC-SHA256(pepper, full_key) as hex. See app/core/api_keys.py.
    """

    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id"), index=True)
    key_prefix: Mapped[str] = mapped_column(String(16), unique=True)
    key_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    agent: Mapped[Agent] = relationship(back_populates="api_keys")


class AgentToolGrant(Base):
    """Explicit allowlist entry: this agent may call this tool. Absence of a row means deny."""

    __tablename__ = "agent_tool_grants"

    agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.id"), primary_key=True)
    tool_name: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    agent: Mapped[Agent] = relationship(back_populates="tool_grants")
