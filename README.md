# GateZero — Zero-Trust Security Gateway for AI Agents

**Runtime security and policy enforcement for AI agent tool calls.**

GateZero is a proposed security gateway designed to sit between LLM-powered agents and Model Context Protocol (MCP) tool servers. It aims to inspect tool calls, enforce access-control policies, detect potentially malicious inputs and outputs, and maintain an auditable record of security decisions.

As AI agents gain access to external tools, APIs, filesystems, and other resources, unrestricted tool execution introduces risks such as unauthorized access, prompt injection, and sensitive-data exposure. GateZero aims to provide a centralized enforcement layer that evaluates tool calls before they reach their intended destinations.

> **Project status:** In development. The architecture and feature set are being defined. Features listed below are planned and should not be considered implemented until verified in the codebase.

## Key Objectives

- **Zero-trust tool access:** Default-deny authorization with explicit per-agent tool allowlists.
- **Argument validation:** Validate tool arguments against schemas and reject potentially unsafe inputs.
- **Prompt-injection defense:** Inspect tool outputs for instruction-like content that could influence agent behavior.
- **Sensitive-data protection:** Detect API keys, tokens, and other secret-like patterns in outbound tool arguments.
- **Rate limiting:** Apply configurable request limits per agent and per tool.
- **Auditability:** Persist security decisions and tool-call metadata for investigation and review.
- **Security observability:** Provide a dashboard for examining agent traffic, policy decisions, and blocked requests.

## Proposed Architecture

```text
             ┌─────────────────────┐
             │     LLM Agent       │
             └──────────┬──────────┘
                        │
                        ▼
             ┌─────────────────────┐
             │   GateZero Proxy    │
             │     (FastAPI)       │
             └──────────┬──────────┘
                        │
                        ▼
             ┌─────────────────────┐
             │ Policy Enforcement  │
             │                     │
             │ • Tool authorization│
             │ • Argument checks   │
             │ • Security policies │
             │ • Rate limiting     │
             └──────────┬──────────┘
                        │
                 Allow / Block
                        │
                        ▼
             ┌─────────────────────┐
             │   MCP Tool Servers  │
             └─────────────────────┘

             Security decisions
                        │
                        ▼
             ┌─────────────────────┐
             │    PostgreSQL       │
             │   Audit Records     │
             └──────────┬──────────┘
                        │
                        ▼
             ┌─────────────────────┐
             │   React Dashboard   │
             │ Traffic & Alerts    │
             └─────────────────────┘
```

*This diagram represents the intended architecture, not a verified implementation.*

## Planned Security Controls

### 1. Default-Deny Tool Authorization

Define which tools each agent is permitted to invoke. Requests that do not match an explicitly approved policy should be denied.

### 2. Schema-Based Argument Validation

Validate tool arguments against their expected schemas. Additional security checks will target path traversal, shell metacharacters, and filesystem paths outside configured boundaries.

### 3. Prompt-Injection Detection

Inspect tool responses for suspicious instruction-like content before returning them to the agent. Detection is intended to identify potential prompt-injection attempts; it does not guarantee that all malicious instructions will be detected.

### 4. Sensitive-Data Detection

Inspect outbound arguments for recognizable secret patterns, including API keys and authentication tokens. This is intended as a basic safeguard against accidental disclosure and some forms of data exfiltration.

### 5. Rate Limiting

Introduce configurable request limits for individual agents and tools to help prevent excessive or abusive tool usage.

### 6. Audit Logging

Record allowed and blocked requests in PostgreSQL, including relevant policy decisions and timestamps. Sensitive values should be redacted or excluded from logs.

## Technology Stack

| Component | Technology |
|---|---|
| Gateway and API | Python, FastAPI |
| Policy enforcement | Python |
| Data persistence | PostgreSQL |
| Dashboard | React |
| Tool integration | Model Context Protocol (MCP) |
| Testing | pytest |
| Version control | Git, GitHub |

*The stack reflects the intended implementation and may evolve during development.*

## Security and Evaluation Goals

The project aims to evaluate:

- Whether unauthorized tool calls are reliably blocked.
- Whether argument-validation rules catch representative malicious inputs.
- How well prompt-injection detection distinguishes suspicious from benign tool outputs.
- Whether sensitive-data patterns are detected without excessive false positives.
- Whether rate limits and audit records behave as expected.
- What latency the gateway introduces to tool execution.

These are evaluation goals, not measured results.

## Security Considerations

GateZero is intended to provide an additional enforcement layer, not a complete solution to agent security.

- Pattern-based detection can miss novel or obfuscated attacks.
- Prompt-injection detection cannot guarantee safe handling of untrusted content.
- Secret scanning cannot identify every form of sensitive data.
- Security decisions depend on correctly configured policies and trusted gateway deployment.
- The gateway itself must be protected against unauthorized configuration changes and direct access to downstream tools.

