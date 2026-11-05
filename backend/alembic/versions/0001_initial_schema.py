"""Initial schema: agents, api_keys, agent_tool_grants, audit_events.

Revision ID: 0001
Revises:
Create Date: 2026-11-04

Allowed values in CHECK constraints are written out literally on purpose: a migration is a
frozen snapshot, so it must not change meaning if the Python enums change later. Adding a new
reason code means writing a new migration that replaces the constraint.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

STAGES = "'auth', 'request', 'policy', 'execution', 'output'"
DECISIONS = "'allow', 'deny'"
OUTCOMES = "'pending', 'executed', 'denied', 'execution_error', 'output_blocked'"
REASON_CODES = (
    "'ALLOWED', 'AUTH_MISSING', 'AUTH_INVALID', 'AUTH_REVOKED', 'AUTH_AGENT_INACTIVE', "
    "'AUTH_WRONG_ROLE', 'REQUEST_TOO_LARGE', 'REQUEST_MALFORMED', 'TOOL_UNKNOWN', "
    "'TOOL_NOT_PERMITTED', 'ARGS_INVALID', 'TOOL_EXECUTION_FAILED', 'AUDIT_UNAVAILABLE'"
)


def upgrade() -> None:
    op.create_table(
        "agents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("role IN ('agent', 'auditor')", name=op.f("ck_agents_role_valid")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agents")),
        sa.UniqueConstraint("name", name=op.f("uq_agents_name")),
    )

    op.create_table(
        "api_keys",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("key_prefix", sa.String(length=16), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["agent_id"], ["agents.id"], name=op.f("fk_api_keys_agent_id_agents")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_api_keys")),
        sa.UniqueConstraint("key_prefix", name=op.f("uq_api_keys_key_prefix")),
    )
    op.create_index(op.f("ix_api_keys_agent_id"), "api_keys", ["agent_id"])

    op.create_table(
        "agent_tool_grants",
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("tool_name", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"], ["agents.id"], name=op.f("fk_agent_tool_grants_agent_id_agents")
        ),
        sa.PrimaryKeyConstraint("agent_id", "tool_name", name=op.f("pk_agent_tool_grants")),
    )

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("request_id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=True),
        sa.Column("tool_name", sa.String(length=64), nullable=True),
        sa.Column("stage", sa.String(length=20), nullable=False),
        sa.Column("decision", sa.String(length=10), nullable=False),
        sa.Column("outcome", sa.String(length=20), nullable=False),
        sa.Column("reason_code", sa.String(length=50), nullable=False),
        sa.Column(
            "findings",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.CheckConstraint(f"stage IN ({STAGES})", name=op.f("ck_audit_events_stage_valid")),
        sa.CheckConstraint(
            f"decision IN ({DECISIONS})", name=op.f("ck_audit_events_decision_valid")
        ),
        sa.CheckConstraint(f"outcome IN ({OUTCOMES})", name=op.f("ck_audit_events_outcome_valid")),
        sa.CheckConstraint(
            f"reason_code IN ({REASON_CODES})", name=op.f("ck_audit_events_reason_code_valid")
        ),
        sa.CheckConstraint(
            "duration_ms IS NULL OR duration_ms >= 0",
            name=op.f("ck_audit_events_duration_non_negative"),
        ),
        sa.CheckConstraint(
            "(decision = 'deny' AND outcome = 'denied') OR "
            "(decision = 'allow' AND outcome <> 'denied')",
            name=op.f("ck_audit_events_decision_outcome_consistent"),
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"], ["agents.id"], name=op.f("fk_audit_events_agent_id_agents")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_events")),
    )
    op.create_index(
        "ix_audit_events_agent_created",
        "audit_events",
        ["agent_id", sa.text("created_at DESC")],
    )
    op.create_index(
        "ix_audit_events_outcome_created",
        "audit_events",
        ["outcome", sa.text("created_at DESC")],
    )
    op.create_index("ix_audit_events_request_id", "audit_events", ["request_id"])


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("agent_tool_grants")
    op.drop_index(op.f("ix_api_keys_agent_id"), table_name="api_keys")
    op.drop_table("api_keys")
    op.drop_table("agents")
