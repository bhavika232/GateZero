"""FastAPI dependencies: DB session, authentication, role checks, size-capped body reading.

Dependency order on POST /v1/tool-calls is deliberate: authentication runs BEFORE the body is
read, so an unauthenticated client can't make the server buffer anything.
"""

import uuid
from collections.abc import Iterator

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.config import Settings
from app.core.audit_service import AuditRecord, AuditService, AuditWriteError
from app.core.auth import AuthenticatedAgent, AuthenticationError, authenticate
from app.core.errors import Decision, GatewayError, Outcome, ReasonCode, Stage
from app.core.request_body import RawBody

# auto_error=False: we want to produce (and audit) our own 401, not FastAPI's default 403.
bearer_scheme = HTTPBearer(
    auto_error=False,
    description="Agent API key: `Authorization: Bearer gz_<prefix>_<secret>`",
)


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


def get_request_id(request: Request) -> uuid.UUID:
    return request.state.request_id


def get_db(request: Request) -> Iterator[Session]:
    session: Session = request.app.state.session_factory()
    try:
        yield session
    finally:
        session.close()


def _audit_auth_failure(
    db: Session,
    request_id: uuid.UUID,
    reason: ReasonCode,
    agent_id: uuid.UUID | None = None,
    findings: list | None = None,
) -> None:
    try:
        AuditService(db).record(
            AuditRecord(
                request_id=request_id,
                agent_id=agent_id,
                stage=Stage.AUTH,
                decision=Decision.DENY,
                outcome=Outcome.DENIED,
                reason_code=reason,
                findings=findings or [],
            )
        )
    except AuditWriteError:
        pass  # logged by AuditService; the request is rejected regardless


def get_authenticated_agent(
    request_id: uuid.UUID = Depends(get_request_id),
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> AuthenticatedAgent:
    presented = credentials.credentials if credentials else None
    try:
        return authenticate(db, presented, settings.api_key_pepper.get_secret_value())
    except AuthenticationError as exc:
        _audit_auth_failure(db, request_id, exc.reason_code, exc.agent_id, exc.findings)
        # The audit log keeps the precise reason; the caller only learns "missing" vs "invalid",
        # so it can't tell a revoked key from a disabled agent from a typo.
        public = (
            ReasonCode.AUTH_MISSING
            if exc.reason_code == ReasonCode.AUTH_MISSING
            else ReasonCode.AUTH_INVALID
        )
        raise GatewayError(
            401,
            public,
            "Missing or invalid API key.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None


def require_tool_caller(
    agent: AuthenticatedAgent = Depends(get_authenticated_agent),
    request_id: uuid.UUID = Depends(get_request_id),
    db: Session = Depends(get_db),
) -> AuthenticatedAgent:
    """Only identities with role 'agent' may list or call tools (auditors can't execute tools)."""
    if agent.role != "agent":
        _audit_auth_failure(db, request_id, ReasonCode.AUTH_WRONG_ROLE, agent.id)
        raise GatewayError(403, ReasonCode.AUTH_WRONG_ROLE, "This identity cannot call tools.")
    return agent


async def read_limited_body(request: Request) -> RawBody:
    """Read the body, stopping as soon as it exceeds the limit.

    Checking Content-Length alone isn't enough: a client can omit it (chunked encoding) or
    lie. So we also count bytes as they stream in and stop early.
    """
    limit: int = request.app.state.settings.max_request_bytes

    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        return RawBody(data=b"", too_large=True)

    chunks: list[bytes] = []
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > limit:
            return RawBody(data=b"", too_large=True)
        chunks.append(chunk)
    return RawBody(data=b"".join(chunks))
