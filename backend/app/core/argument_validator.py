"""Validate tool arguments against the registered tool's schema.

Current scope (vertical slice): strict Pydantic schema validation only, meaning
wrong types, missing fields, unknown fields, and per-field length limits.

Planned (Phase 3, steps 4–5): tool-specific checks such as path containment for read_file.

Security detail: Pydantic error objects include the offending `input` value. That value could
be a secret the agent tried to send somewhere, so we strip it before the errors leave this
module. Only the field location, error type and generic message are kept.
"""

from typing import Any

from pydantic import BaseModel, ValidationError

from app.tools.registry import ToolSpec

MAX_ERROR_DETAILS = 10


class ArgumentValidationError(Exception):
    def __init__(self, details: list[dict[str, Any]]) -> None:
        super().__init__("tool arguments failed validation")
        self.details = details


def sanitize_validation_errors(exc: ValidationError) -> list[dict[str, Any]]:
    """Reduce Pydantic errors to {loc, type, msg}, dropping input values and context."""
    sanitized = []
    for error in exc.errors(include_input=False, include_context=False, include_url=False):
        sanitized.append(
            {
                "loc": [str(part) for part in error["loc"]],
                "type": error["type"],
                "msg": error["msg"],
            }
        )
    return sanitized[:MAX_ERROR_DETAILS]


def validate_arguments(spec: ToolSpec, arguments: dict[str, Any]) -> BaseModel:
    try:
        return spec.args_model.model_validate(arguments)
    except ValidationError as exc:
        raise ArgumentValidationError(sanitize_validation_errors(exc)) from exc
