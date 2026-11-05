"""POST /v1/tool-calls — the gateway endpoint.

The route is thin on purpose: it wires dependencies together and hands off to GatewayService,
which owns the whole security lifecycle.

We read the body ourselves (read_limited_body) instead of declaring a Pydantic body parameter,
because FastAPI would otherwise parse and reject malformed bodies *before* our code runs, and
those rejections would never reach the audit log. `openapi_extra` keeps the schema in /docs.
"""

import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_request_id, read_limited_body, require_tool_caller
from app.core.audit_service import AuditService
from app.core.auth import AuthenticatedAgent
from app.core.request_body import RawBody
from app.schemas.errors import ErrorResponse
from app.schemas.tool_call import ToolCallRequest, ToolCallResponse
from app.services.gateway_service import GatewayService

router = APIRouter(prefix="/v1", tags=["tool-calls"])

_ERRORS = {
    400: {"model": ErrorResponse, "description": "Malformed request body"},
    401: {"model": ErrorResponse, "description": "Missing or invalid API key"},
    403: {"model": ErrorResponse, "description": "Tool not permitted or identity cannot call tools"},
    413: {"model": ErrorResponse, "description": "Body exceeds size limit"},
    422: {"model": ErrorResponse, "description": "Tool arguments failed validation"},
    502: {"model": ErrorResponse, "description": "Tool execution failed (audited)"},
    503: {"model": ErrorResponse, "description": "Audit log unavailable; call NOT executed"},
}


@router.post(
    "/tool-calls",
    response_model=ToolCallResponse,
    responses=_ERRORS,
    summary="Submit a tool call through the gateway",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": ToolCallRequest.model_json_schema()}},
        }
    },
)
def submit_tool_call(
    request: Request,
    # Order matters: authenticate first, then read the body.
    agent: AuthenticatedAgent = Depends(require_tool_caller),
    body: RawBody = Depends(read_limited_body),
    request_id: uuid.UUID = Depends(get_request_id),
    db: Session = Depends(get_db),
) -> ToolCallResponse:
    service = GatewayService(request.app.state.registry, AuditService(db))
    return service.handle(agent, body, request_id)
