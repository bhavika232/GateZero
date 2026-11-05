"""Demonstration tool handlers and their argument schemas.

Rules every handler follows:
- It receives an already-validated Pydantic model, never raw JSON.
- It never calls a shell, never imports modules by name, never fetches URLs chosen by the caller.
- It returns plain text (the output scanner added later inspects text).

Argument models use `extra="forbid"` (unknown fields are an error) and explicit size limits.
"""

from pydantic import BaseModel, ConfigDict, Field


class StrictArgs(BaseModel):
    """Base for every tool's arguments: no extra fields, no silent type coercion."""

    model_config = ConfigDict(extra="forbid", strict=True)


class EchoArgs(StrictArgs):
    text: str = Field(min_length=1, max_length=1_000)


def echo(args: EchoArgs) -> str:
    """Return the input unchanged. The simplest possible tool, used for the vertical slice."""
    return args.text


class WordCountArgs(StrictArgs):
    text: str = Field(min_length=1, max_length=10_000)


def word_count(args: WordCountArgs) -> str:
    """Count whitespace-separated words. Pure function, no side effects."""
    return str(len(args.text.split()))
