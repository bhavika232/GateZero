# GateZero

A zero-trust security gateway that sits between an AI agent and the tools it wants to call.
Every tool call is authenticated, checked against a default-deny allowlist, validated, and
recorded in PostgreSQL before anything executes.

> **Status: early development.** This is a generic tool-call gateway, not an MCP proxy.
> MCP protocol support is a future goal and is not implemented.

## What works today vs. what's planned

| Area | Status |
|---|---|
| Per-agent API keys (HMAC-SHA256 hashed, peppered, constant-time compare) | Implemented |
| Server-controlled tool registry (`echo`, `word_count`) | Implemented |
| Default-deny allowlist per agent | Implemented |
| Request size cap (Content-Length and streamed byte count) | Implemented |
| Strict request and argument schemas (no extra fields, no type coercion) | Implemented |
| PostgreSQL audit log, two-phase and fail-closed for allowed calls | Implemented |
| Audit of auth failures, denials, execution errors | Implemented |
| `GET /health`, `GET /ready`, `POST /v1/tool-calls`, `GET /v1/tools` | Implemented |
| Seed/admin CLI (create agent, issue/revoke key, grant tool) | Implemented |
| Sandboxed `read_file` tool with path containment | Planned (step 5) |
| Secret scanning of arguments | Planned (step 6) — stub in `app/core/secret_scanner.py` |
| Rate limiting (per agent, per tool, per IP for failed auth) | Planned (step 7) — stub |
| Prompt-injection detection on tool output | Planned (step 8) — stub |
| `GET /v1/audit-events` (auditor role) | Planned (step 9) |
| Threat model document | Planned |

"Implemented" means the code exists and has tests. See *Testing* for what has actually been run.

---

## Setup on Windows (PowerShell)

### 1. Install the tools

- **uv** (manages Python, the virtual environment and the lockfile):
  ```powershell
  powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
  ```
  Close and reopen PowerShell, then check: `uv --version`
- **PostgreSQL 15 or newer**: download the Windows installer from
  <https://www.postgresql.org/download/windows/>. Remember the password you set for the
  `postgres` superuser. Then add its `bin` folder to PATH so `psql` works, for example:
  ```powershell
  # adjust 17 to the version you installed
  [Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Program Files\PostgreSQL\17\bin", "User")
  ```
  Reopen PowerShell, then check: `psql --version`
- **Git**: `git --version`

You don't need to install Python separately: `uv` reads `.python-version` (3.12) and
downloads it if needed.

### 2. Install dependencies

From the repo root:

```powershell
uv sync
```

This creates `.venv\` and `uv.lock`. **Commit `uv.lock`**: it pins the exact version of every
package so everyone (and CI) gets the same environment. `uv run <command>` runs anything
inside the virtual environment without activating it.

### 3. Create the databases

```powershell
psql -U postgres
```

Then, inside `psql` (pick your own password):

```sql
CREATE ROLE gatezero_app WITH LOGIN PASSWORD 'choose-a-strong-password';
CREATE DATABASE gatezero OWNER gatezero_app;
CREATE DATABASE gatezero_test OWNER gatezero_app;
\q
```

The app uses its own non-superuser role, so a bug in the app can't, for example, drop other
databases. `gatezero_test` is wiped by the test suite; never point it at real data.

### 4. Configure

```powershell
Copy-Item .env.example .env
uv run python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Open `.env` and set:
- `GATEZERO_DATABASE_URL` and `GATEZERO_TEST_DATABASE_URL` with your password.
  If the password contains `@ : / % #`, URL-encode it (e.g. `@` → `%40`).
- `GATEZERO_API_KEY_PEPPER` to the random value printed above.

`.env` is in `.gitignore`. Never commit it.

### 5. Run the migrations

```powershell
uv run alembic upgrade head
```

Expected: `Running upgrade  -> 0001, Initial schema: ...`. Check with
`psql -U gatezero_app -d gatezero -c "\dt"`: you should see `agents`, `api_keys`,
`agent_tool_grants`, `audit_events`, `alembic_version`.

### 6. Create an agent and a key

```powershell
uv run python -m app.cli create-agent demo-agent
uv run python -m app.cli grant demo-agent echo
uv run python -m app.cli issue-key demo-agent
```

The last command prints a key like `gz_3f9a1c0b7e2d_…` **once**. Copy it now; only its hash is stored.

### 7. Start the server

```powershell
uv run uvicorn app.main:create_app --factory --reload
```

Open <http://127.0.0.1:8000/docs>, click **Authorize**, paste the key, and try the endpoints.

### 8. Make a call from PowerShell

```powershell
$key  = "gz_paste_your_key_here"
$body = @{ tool = "echo"; arguments = @{ text = "hello gateway" } } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/v1/tool-calls `
  -Headers @{ Authorization = "Bearer $key" } -ContentType "application/json" -Body $body
```

Expected shape (IDs will differ):

```json
{
  "request_id": "6b1f…",
  "audit_event_id": "c2a4…",
  "tool": "echo",
  "status": "executed",
  "output": "hello gateway"
}
```

Now try `tool = "word_count"` (not granted). You should get **403** with:

```json
{"error": {"code": "TOOL_NOT_PERMITTED", "message": "This agent is not permitted to call that tool.", "request_id": "…"}}
```

Windows PowerShell 5.1 turns non-2xx responses into exceptions. The Swagger UI at `/docs` is
the easiest way to see denial bodies. Then look at the audit log:

```powershell
psql -U gatezero_app -d gatezero -c "SELECT created_at, tool_name, decision, outcome, reason_code FROM audit_events ORDER BY created_at DESC LIMIT 10;"
```

---

## Testing and linting

```powershell
uv run pytest              # all tests
uv run pytest tests/unit   # no database needed
uv run ruff check .
uv run ruff format --check .
```

- `tests/unit/`: pure logic (keys, policy, schemas, registry). No database.
- `tests/integration/`: the real app against the real `gatezero_test` database. It rebuilds
  the schema via Alembic at the start of each run and truncates tables before each test. If
  `GATEZERO_TEST_DATABASE_URL` isn't set, these tests are **skipped** (shown in the summary),
  not silently passed. The run refuses to start if the database name doesn't end in `_test`.

---

## API

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /health` | none | Process is up |
| `GET /ready` | none | Database reachable (returns only up/down) |
| `POST /v1/tool-calls` | agent key, role `agent` | Submit a tool call |
| `GET /v1/tools` | agent key, role `agent` | Tools *this* agent may call, with argument schemas |

Every response carries an `X-Request-ID` header (server-generated; client-supplied values
are ignored). Every error uses the same envelope:
`{"error": {"code", "message", "request_id", "details?"}}`.

Status codes for `POST /v1/tool-calls`: 200 executed · 400 malformed · 401 bad/missing key ·
403 not permitted · 413 too large · 422 bad arguments · 502 tool failed · 503 audit
unavailable (tool **not** executed).

## Request lifecycle

1. Authenticate the API key. Identity comes only from the key, never from the body.
2. Read the body with a hard byte cap (only after authentication).
3. Reject oversized bodies.
4. Parse and validate the envelope `{tool, arguments}`. Unknown fields such as `agent_id` are rejected.
5. Look up the tool in the in-code registry and apply the agent's allowlist (default deny).
6. Validate arguments against the tool's strict schema.
7. *(planned)* tool-specific checks: path containment.
8. *(planned)* secret scan of arguments.
9. *(planned)* rate limits. The per-agent check will run right after step 1.
10. **Audit phase 1**: insert `allow / pending`. If this fails, stop with 503 (fail closed).
11. Execute the registered handler.
12. *(planned)* prompt-injection scan of the output.
13. **Audit phase 2**: update the row to `executed` or `execution_error`.
14. Return the structured response.

## When audit records are written

| Situation | Rows | agent_id | decision / outcome |
|---|---|---|---|
| Missing, invalid or revoked key | 1 | NULL | deny / denied |
| Valid key, disabled agent or wrong role | 1 | set | deny / denied |
| Too large, malformed, not permitted, bad arguments | 1, before the response | set | deny / denied |
| Allowed call | 1, inserted then updated | set | allow / pending → executed or execution_error |

Never stored: API keys, request bodies, argument values, tool output. Validation findings keep
only the field location and error type. Failed auth stores a short SHA-256 fingerprint of the
key prefix, never the key.

If writing a **deny** fails, the request is still denied. If writing the **allow** fails, the
tool doesn't run. A row left in `pending` means the tool ran but its outcome couldn't be
recorded. Operators should query for these.

The database enforces consistency too: CHECK constraints reject unknown stages, outcomes and
reason codes, and reject any row that says `deny` but `executed`.

## Key security decisions

- **Tools live in code, permissions live in the DB.** A grant row can only name a tool. It
  can't create one, and the name is re-checked against the registry on every call.
- **Unknown vs. not-permitted look the same to the caller** (`TOOL_NOT_PERMITTED`), so agents
  can't probe which tools exist. The audit log keeps the precise reason.
- **Auth failures are vague to the caller** (`AUTH_MISSING` / `AUTH_INVALID`) but precise in
  the audit log (`AUTH_REVOKED`, `AUTH_AGENT_INACTIVE`, …).
- **HMAC-SHA256 with a pepper, not bcrypt/Argon2**, because keys have 256 bits of entropy, so
  slow hashing adds latency without adding security. See `app/core/api_keys.py`.
- **No HTTP endpoint changes permissions.** Agents, keys and grants are managed by the CLI,
  run on the server.
- **`/docs` and `/openapi.json` are disabled** when `GATEZERO_ENVIRONMENT=production`.

## Known limitations (current)

- No rate limiting yet. Failed authentication is audited, so an unauthenticated client could
  fill the audit table. **Don't expose the server beyond localhost** until step 7.
- Tool handlers run in-process with no timeout or resource isolation.
- No secret scanning or output-injection detection yet. The stubs say so explicitly and are
  not wired in.
- Single-process assumptions. The future in-memory rate limiter won't be shared across workers.
- Production would also need TLS termination, key rotation tooling, secret management for
  the pepper, and log shipping/retention.

## Project layout

```
app/
  main.py                 app factory, exception handlers, router wiring
  config.py               typed settings from environment / .env
  cli.py                  admin CLI: agents, keys, grants
  api/
    deps.py               DB session, auth, role check, size-capped body reader
    middleware.py         X-Request-ID
    routes/               health, tool_calls, tools
  core/                   security logic (no HTTP inside)
    api_keys.py           key format, hashing, verification
    auth.py               key -> AuthenticatedAgent
    policy_engine.py      default-deny authorization
    argument_validator.py schema validation + error sanitizing
    audit_service.py      the only writer of audit_events
    errors.py             reason codes, stages, outcomes, GatewayError
    request_body.py       RawBody passed from HTTP layer to the service
    secret_scanner.py     (stub)  injection_detector.py (stub)  rate_limiter.py (stub)
  services/
    gateway_service.py    the lifecycle above, step by step
  tools/
    registry.py           ToolSpec, ToolRegistry
    handlers.py           demo tools and their argument schemas
  models/                 SQLAlchemy models
  db/                     engine, session, declarative base
  schemas/                Pydantic request/response models
alembic/                  migrations
tests/
  unit/                   no DB
  integration/            real app + real test DB
```

## Dependencies

| Package | Why |
|---|---|
| FastAPI + Uvicorn | HTTP API and OpenAPI docs; ASGI server |
| Pydantic v2, pydantic-settings | request/argument validation; typed config from env |
| SQLAlchemy 2.0 (sync) | ORM with typed `Mapped[...]` models; sync keeps the code simple |
| psycopg 3 (binary) | maintained PostgreSQL driver with Windows wheels |
| Alembic | versioned schema migrations |
| pytest, HTTPX | tests; FastAPI's TestClient is built on HTTPX |
| Ruff | lint (including bandit-style `S` security rules) and formatting |

No password-hashing library is needed: `hmac`, `hashlib` and `secrets` from the standard
library cover high-entropy API keys.
