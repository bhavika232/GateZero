"""Rate limiting — NOT IMPLEMENTED YET (Phase 3, step 7).

Planned design (approved):
- Sliding-window counter keyed by the AUTHENTICATED agent id (never a caller-supplied id).
- Per-agent limit checked right after authentication; per-(agent, tool) limit right after
  the tool lookup. This means malformed or denied requests still consume quota, so they
  can't be used to hammer the gateway for free.
- A coarse per-client-IP limit on failed authentication, so unauthenticated traffic can't
  flood the audit table (failed auth is audited with agent_id = NULL).
- A small RateLimiter protocol so the in-memory backend can later be swapped for Redis.

MVP limitation to document: in-memory counters reset on restart and are not shared across
multiple worker processes.

Until this lands, failed-authentication auditing has no flood protection. Don't expose the
server beyond localhost before step 7.
"""
