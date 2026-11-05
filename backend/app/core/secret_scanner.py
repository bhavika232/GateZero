"""Outbound secret detection — NOT IMPLEMENTED YET (Phase 3, step 6).

Planned design:
- A list of configurable rules: (rule_id, compiled regex), e.g. AWS access key IDs,
  GitHub tokens, generic "sk-..." style API keys, PEM private-key headers, JWT-shaped strings.
- scan(arguments) walks every string in the validated arguments and returns findings like
  {"rule": "github_token", "path": ["text"]} — never the matched value itself.
- The gateway denies the call with SECRET_DETECTED before execution.

Known limits (to document in the README): regexes can't catch encoded, split, or novel secret
formats, and can't stop exfiltration through tool semantics. This is a tripwire, not a DLP system.

This module is intentionally not wired into the gateway yet, so nothing can mistakenly rely on it.
"""
