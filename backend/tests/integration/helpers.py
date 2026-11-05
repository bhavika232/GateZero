"""Small helpers shared by integration tests (kept out of conftest.py so they import cleanly)."""

import json
import uuid

from sqlalchemy import select

from app.models import AuditEvent

TEST_MAX_REQUEST_BYTES = 2048


def bearer(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def audit_events_for(db, response) -> list[AuditEvent]:
    """All audit rows for the request that produced `response`, via the X-Request-ID header."""
    request_id = uuid.UUID(response.headers["X-Request-ID"])
    db.expire_all()
    return list(
        db.scalars(select(AuditEvent).where(AuditEvent.request_id == request_id)).all()
    )


def only_event(db, response) -> AuditEvent:
    events = audit_events_for(db, response)
    assert len(events) == 1, f"expected exactly one audit event, got {len(events)}"
    return events[0]


def dumps(event: AuditEvent) -> str:
    """Serialize every column of an audit row, to assert something is NOT stored anywhere."""
    return json.dumps({c.name: str(getattr(event, c.name)) for c in AuditEvent.__table__.columns})
