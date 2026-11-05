"""The raw request body as handed from the HTTP layer to the gateway service."""

from dataclasses import dataclass


@dataclass(frozen=True)
class RawBody:
    data: bytes
    # True when the body exceeded max_request_bytes. Reading stopped early, so `data` is empty.
    too_large: bool = False
