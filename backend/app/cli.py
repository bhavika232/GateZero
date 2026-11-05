"""Controlled seed / administration CLI. Runs on the server with direct DB access.

This is the MVP's only way to create agents, issue keys and grant tools. There is no HTTP
endpoint that changes permissions, so a compromised agent can't grant itself anything.

Usage (from the repo root):
  uv run python -m app.cli create-agent demo-agent
  uv run python -m app.cli create-agent ops-auditor --role auditor
  uv run python -m app.cli issue-key demo-agent
  uv run python -m app.cli grant demo-agent echo
  uv run python -m app.cli revoke-key <prefix>
  uv run python -m app.cli list-agents
"""

import argparse
import sys
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.api_keys import generate_key
from app.db.session import build_engine, build_session_factory
from app.models.agent import AGENT_ROLES, Agent, AgentToolGrant, ApiKey
from app.tools.registry import build_default_registry


def _get_agent(session: Session, name: str) -> Agent:
    agent = session.scalar(select(Agent).where(Agent.name == name))
    if agent is None:
        sys.exit(f"error: no agent named {name!r}")
    return agent


def create_agent(session: Session, name: str, role: str) -> None:
    session.add(Agent(name=name, role=role))
    try:
        session.commit()
    except IntegrityError:
        sys.exit(f"error: agent {name!r} already exists")
    print(f"created agent {name!r} (role={role})")


def issue_key(session: Session, name: str, pepper: str) -> None:
    agent = _get_agent(session, name)
    key = generate_key(pepper)
    session.add(ApiKey(agent_id=agent.id, key_prefix=key.prefix, key_hash=key.key_hash))
    session.commit()
    print("API key (shown ONCE — store it somewhere safe, it cannot be recovered):")
    print(key.plaintext)
    print(f"prefix: {key.prefix}  (use this to revoke it)")


def grant(session: Session, name: str, tool: str) -> None:
    registry = build_default_registry()
    if registry.get(tool) is None:
        sys.exit(f"error: {tool!r} is not a registered tool. Known: {sorted(registry.names())}")
    agent = _get_agent(session, name)
    if agent.role != "agent":
        sys.exit(f"error: {name!r} has role {agent.role!r}; only role 'agent' can call tools")
    session.add(AgentToolGrant(agent_id=agent.id, tool_name=tool))
    try:
        session.commit()
    except IntegrityError:
        sys.exit(f"error: {name!r} already has {tool!r}")
    print(f"granted {tool!r} to {name!r}")


def revoke_key(session: Session, prefix: str) -> None:
    key = session.scalar(select(ApiKey).where(ApiKey.key_prefix == prefix))
    if key is None:
        sys.exit(f"error: no key with prefix {prefix!r}")
    if key.revoked_at is not None:
        sys.exit("error: key already revoked")
    key.revoked_at = datetime.now(UTC)
    session.commit()
    print(f"revoked key {prefix}")


def list_agents(session: Session) -> None:
    for agent in session.scalars(select(Agent).order_by(Agent.name)):
        tools = sorted(g.tool_name for g in agent.tool_grants)
        active_keys = [k.key_prefix for k in agent.api_keys if k.revoked_at is None]
        status = "active" if agent.is_active else "disabled"
        print(f"{agent.name}  role={agent.role}  {status}  tools={tools}  keys={active_keys}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="GateZero admin CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("create-agent")
    p.add_argument("name")
    p.add_argument("--role", choices=AGENT_ROLES, default="agent")

    p = sub.add_parser("issue-key")
    p.add_argument("name")

    p = sub.add_parser("grant")
    p.add_argument("name")
    p.add_argument("tool")

    p = sub.add_parser("revoke-key")
    p.add_argument("prefix")

    sub.add_parser("list-agents")

    args = parser.parse_args(argv)
    settings = get_settings()
    engine = build_engine(settings.database_url.get_secret_value())
    try:
        with build_session_factory(engine)() as session:
            if args.command == "create-agent":
                create_agent(session, args.name, args.role)
            elif args.command == "issue-key":
                issue_key(session, args.name, settings.api_key_pepper.get_secret_value())
            elif args.command == "grant":
                grant(session, args.name, args.tool)
            elif args.command == "revoke-key":
                revoke_key(session, args.prefix)
            elif args.command == "list-agents":
                list_agents(session)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
