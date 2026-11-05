"""Request-ID middleware.

Every request gets a fresh server-generated UUID, stored on request.state.request_id and
returned in the X-Request-ID response header. It is the correlation key in the audit log.

We deliberately ignore any X-Request-ID sent by the client: a caller-controlled value in our
logs could be used to forge or confuse correlation, or to inject junk into log lines.

Written as plain ASGI middleware (rather than @app.middleware("http")) because it's small and
doesn't interfere with streaming request bodies.
"""

import uuid

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class RequestIdMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = uuid.uuid4()
        scope.setdefault("state", {})["request_id"] = request_id

        async def send_with_request_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["X-Request-ID"] = str(request_id)
            await send(message)

        await self.app(scope, receive, send_with_request_id)
