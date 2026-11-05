"""Default-deny tool authorization. Pure and deterministic: same inputs, same decision.

Inputs come only from trusted sources:
- `registered_tools`: the in-code registry
- `granted_tools`:    the authenticated agent's grants, loaded from the DB by the server
Nothing in the request body can influence either set.

Information-leak note: we distinguish TOOL_UNKNOWN from TOOL_NOT_PERMITTED in the *audit log*
(useful to an operator), but the gateway shows the caller TOOL_NOT_PERMITTED for both. If the
caller could tell the two apart, it could probe which tools exist on the server.
"""

from dataclasses import dataclass

from app.core.errors import ReasonCode


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason_code: ReasonCode


def authorize_tool(
    tool_name: str,
    registered_tools: frozenset[str],
    granted_tools: frozenset[str],
) -> PolicyDecision:
    # Order matters only for the audit reason: an unregistered tool is "unknown" even if a
    # stale grant row still names it.
    if tool_name not in registered_tools:
        return PolicyDecision(allowed=False, reason_code=ReasonCode.TOOL_UNKNOWN)
    if tool_name not in granted_tools:
        return PolicyDecision(allowed=False, reason_code=ReasonCode.TOOL_NOT_PERMITTED)
    return PolicyDecision(allowed=True, reason_code=ReasonCode.ALLOWED)
