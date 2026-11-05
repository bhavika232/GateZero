"""GET /v1/tools — the tools the calling agent may use. Never other agents' grants."""

from fastapi import APIRouter, Depends, Request

from app.api.deps import require_tool_caller
from app.core.auth import AuthenticatedAgent
from app.schemas.errors import ErrorResponse
from app.schemas.tool_call import ToolInfo, ToolListResponse

router = APIRouter(prefix="/v1", tags=["tools"])


@router.get(
    "/tools",
    response_model=ToolListResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    summary="List tools this agent is permitted to call",
)
def list_tools(
    request: Request, agent: AuthenticatedAgent = Depends(require_tool_caller)
) -> ToolListResponse:
    registry = request.app.state.registry
    tools = []
    # Intersection: a stale grant for a tool that no longer exists is simply not shown.
    for name in sorted(agent.granted_tools & registry.names()):
        spec = registry.get(name)
        tools.append(
            ToolInfo(
                name=spec.name,
                description=spec.description,
                arguments_schema=spec.args_model.model_json_schema(),
            )
        )
    return ToolListResponse(tools=tools)
