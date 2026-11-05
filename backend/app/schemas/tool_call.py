"""Request and response models for POST /v1/tool-calls and GET /v1/tools.

Note there is no `agent_id` field: identity comes only from the API key. Because of
extra="forbid", a request that tries to send `agent_id` (or `permissions`, `handler`, ...) is
rejected as malformed rather than silently ignored.
"""

import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ToolCallRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$", examples=["echo"])
    arguments: dict[str, Any] = Field(default_factory=dict, examples=[{"text": "hello"}])


class ToolCallResponse(BaseModel):
    request_id: uuid.UUID
    audit_event_id: uuid.UUID
    tool: str
    status: Literal["executed"]
    output: str


class ToolInfo(BaseModel):
    name: str
    description: str
    arguments_schema: dict[str, Any]


class ToolListResponse(BaseModel):
    tools: list[ToolInfo]
