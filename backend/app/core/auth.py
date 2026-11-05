"""Authenticate an API key and build the trusted identity used for every later decision.

This module knows nothing about HTTP. The FastAPI glue (reading the Authorization header,
turning failures into 401s, auditing them) lives in app/api/deps.py.

The returned AuthenticatedAgent is the ONLY source of identity for the rest of the request.
Nothing in the request body can change who the caller is or what they may do.
"""

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.api_keys import DUMMY_HASH, fingerprint_prefix, parse_key, verify_key
from app.core.errors import ReasonCode
from app.models.agent import AgentToolGrant, ApiKey


@dataclass(frozen=True)
class AuthenticatedAgent:
    id: uuid.UUID
    name: str
    role: str
    granted_tools: frozenset[str]


class AuthenticationError(Exception):
    def __init__(
        self,
        reason_code: ReasonCode,
        agent_id: uuid.UUID | None = None,
        findings: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(reason_code.value)
        self.reason_code = reason_code
        # Set only when the key itself was valid (e.g. agent disabled): identity is trusted.
        self.agent_id = agent_id
        self.findings = findings or []


def authenticate(session: Session, presented_key: str | None, pepper: str) -> AuthenticatedAgent:
    if not presented_key:
        raise AuthenticationError(ReasonCode.AUTH_MISSING)

    parsed = parse_key(presented_key)
    if parsed is None:
        # Not even shaped like a GateZero key; nothing about it is worth recording.
        raise AuthenticationError(ReasonCode.AUTH_INVALID)

    findings = [{"type": "key_prefix_fingerprint", "value": fingerprint_prefix(parsed.prefix)}]

    row = session.scalar(select(ApiKey).where(ApiKey.key_prefix == parsed.prefix))
    # Always run the comparison, even for an unknown prefix, so both failure paths cost the same.
    stored_hash = row.key_hash if row is not None else DUMMY_HASH
    key_matches = verify_key(parsed.full_key, stored_hash, pepper)

    if row is None or not key_matches:
        raise AuthenticationError(ReasonCode.AUTH_INVALID, findings=findings)
    if row.revoked_at is not None:
        raise AuthenticationError(ReasonCode.AUTH_REVOKED, findings=findings)

    agent = row.agent
    if not agent.is_active:
        raise AuthenticationError(
            ReasonCode.AUTH_AGENT_INACTIVE, agent_id=agent.id, findings=findings
        )

    granted = session.scalars(
        select(AgentToolGrant.tool_name).where(AgentToolGrant.agent_id == agent.id)
    ).all()

    return AuthenticatedAgent(
        id=agent.id, name=agent.name, role=agent.role, granted_tools=frozenset(granted)
    )
