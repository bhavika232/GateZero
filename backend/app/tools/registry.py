"""Server-controlled tool registry.

This is the ONLY place tools come from. A caller sends a tool *name*; the gateway looks that
name up here and calls the Python function we registered. The caller can never supply a
module path, function name, executable or URL to run.

To make the registry replaceable in tests (e.g. a deliberately failing tool), the app holds a
ToolRegistry instance on app.state rather than using a global.
"""

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from app.tools.handlers import EchoArgs, WordCountArgs, echo, word_count

TOOL_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    args_model: type[BaseModel]
    handler: Callable[[Any], str]

    def __post_init__(self) -> None:
        if not TOOL_NAME_PATTERN.fullmatch(self.name):
            raise ValueError(f"invalid tool name: {self.name!r}")
        if self.args_model.model_config.get("extra") != "forbid":
            # Fail at startup rather than silently accept unexpected arguments at runtime.
            raise ValueError(f"tool {self.name!r}: args_model must set extra='forbid'")


class ToolRegistry:
    def __init__(self, specs: Iterable[ToolSpec] = ()) -> None:
        self._tools: dict[str, ToolSpec] = {}
        for spec in specs:
            self.register(spec)

    def register(self, spec: ToolSpec) -> None:
        if spec.name in self._tools:
            raise ValueError(f"tool {spec.name!r} is already registered")
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def names(self) -> frozenset[str]:
        return frozenset(self._tools)


def build_default_registry() -> ToolRegistry:
    return ToolRegistry(
        [
            ToolSpec(
                name="echo",
                description="Returns the given text unchanged.",
                args_model=EchoArgs,
                handler=echo,
            ),
            ToolSpec(
                name="word_count",
                description="Counts whitespace-separated words in the given text.",
                args_model=WordCountArgs,
                handler=word_count,
            ),
        ]
    )
