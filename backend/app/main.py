"""Application factory.

Run with:  uv run uvicorn app.main:create_app --factory --reload

A factory (instead of a module-level `app = FastAPI()`) means importing this module never
reads environment variables or opens a DB pool, and tests can build an app with their own
settings and tool registry.
"""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.middleware import RequestIdMiddleware
from app.api.routes import health, tool_calls, tools
from app.config import Settings, get_settings
from app.core.errors import GatewayError
from app.db.session import build_engine, build_session_factory
from app.schemas.errors import ErrorBody, ErrorResponse
from app.tools.registry import ToolRegistry, build_default_registry

logger = logging.getLogger("gatezero")


def _error_response(
    request: Request,
    status_code: int,
    code: str,
    message: str,
    details: list[dict[str, Any]] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    body = ErrorResponse(
        error=ErrorBody(
            code=code,
            message=message,
            request_id=getattr(request.state, "request_id", None),
            details=details,
        )
    )
    return JSONResponse(
        status_code=status_code,
        content=body.model_dump(mode="json", exclude_none=True),
        headers=headers,
    )


def _register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(GatewayError)
    async def gateway_error(request: Request, exc: GatewayError) -> JSONResponse:
        return _error_response(
            request, exc.status_code, exc.public_code.value, exc.message, exc.details, exc.headers
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        codes = {404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED"}
        return _error_response(
            request,
            exc.status_code,
            codes.get(exc.status_code, f"HTTP_{exc.status_code}"),
            str(exc.detail),
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Same sanitizing idea as argument_validator: never echo the rejected input back.
        details = [
            {"loc": [str(p) for p in e.get("loc", ())], "type": e.get("type"), "msg": e.get("msg")}
            for e in exc.errors()
        ][:10]
        return _error_response(request, 422, "REQUEST_MALFORMED", "Invalid request.", details)

    @app.exception_handler(Exception)
    async def unhandled_error(request: Request, exc: Exception) -> JSONResponse:
        # Full traceback goes to the server log; the client gets nothing internal.
        logger.exception("unhandled error")
        return _error_response(request, 500, "INTERNAL_ERROR", "Internal server error.")


def create_app(settings: Settings | None = None, registry: ToolRegistry | None = None) -> FastAPI:
    settings = settings or get_settings()
    engine = build_engine(settings.database_url.get_secret_value())

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        engine.dispose()

    show_docs = settings.environment != "production"
    app = FastAPI(
        title="GateZero",
        version="0.1.0",
        description="Zero-trust security gateway for AI agent tool calls (MVP, in development).",
        docs_url="/docs" if show_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if show_docs else None,
        lifespan=lifespan,
    )

    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = build_session_factory(engine)
    app.state.registry = registry or build_default_registry()

    app.add_middleware(RequestIdMiddleware)
    _register_exception_handlers(app)

    app.include_router(health.router)
    app.include_router(tool_calls.router)
    app.include_router(tools.router)
    return app
