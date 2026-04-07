"""End-to-end request lifecycle integration test (#10 Round 3).

Wires the real production classes from TDD rounds 1-3 — TenantRateLimiter,
LicenseGuard + AgentRegistryCounter, AuditLogRepository, EventBuffer — and
exercises the full chain in a single in-process test:

    request → rate-limit → license-gate → agent-run → audit-log → ws-replay

The goal is not to mock anything: we use the actual production classes so
that any breaking change in one layer cascades into a real test failure here.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import JSON, DateTime, String
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from shieldops.api.middleware.tenant_rate_limiter import TenantRateLimiter
from shieldops.api.ws.event_buffer import EventBuffer
from shieldops.db.repositories.audit_log import AuditLogRepository
from shieldops.licensing.guard import LicenseExceededError, LicenseGuard
from shieldops.licensing.models import License, LicenseTier
from shieldops.licensing.registry_counter import (
    InMemoryAgentRegistry,
    install_registry_counter,
)


class _TestBase(DeclarativeBase):
    pass


class _TestAuditLog(_TestBase):
    __tablename__ = "audit_log_e2e"
    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: f"al-{uuid4().hex[:12]}"
    )
    org_id: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(128))
    actor: Mapped[str] = mapped_column(String(128), default="")
    target: Mapped[str] = mapped_column(String(256), default="")
    result: Mapped[str] = mapped_column(String(32), default="")
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


@pytest_asyncio.fixture()
async def session(monkeypatch: pytest.MonkeyPatch) -> AsyncSession:
    from shieldops.db.repositories import audit_log as mod

    monkeypatch.setattr(mod, "AuditLogRecord", _TestAuditLog)

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(_TestBase.metadata.create_all)
    Session = async_sessionmaker(engine, expire_on_commit=False)
    async with Session() as s:
        yield s
    await engine.dispose()


@pytest.mark.asyncio
async def test_full_request_lifecycle_e2e(session: AsyncSession) -> None:
    """Six requests through every production layer for a single org.

    Layout:
      - Rate limiter starter capacity = 5 → request 6 must be 429
      - License agent_limit = 2 → starting agent 3 must be denied
      - Successful agent runs → 1 audit log entry + 1 buffered event each
    """
    org_id = "org-e2e"

    # --- Layer 1: rate limiter ------------------------------------------------
    rate_limiter = TenantRateLimiter(
        tier_capacities={"starter": (5, 1.0)},
        tier_for_org=lambda _org: "starter",
    )

    # --- Layer 2: license guard wired to a real registry --------------------
    registry = InMemoryAgentRegistry()
    license = License(
        org_id=org_id,
        tier=LicenseTier.STARTER,
        agent_limit=2,
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(days=30),
        signature="test-sig",
    )
    guard = LicenseGuard(license=license)
    install_registry_counter(guard=guard, registry=registry)

    # --- Layer 3: persistence + audit log ------------------------------------
    audit_repo = AuditLogRepository(session)

    # --- Layer 4: real-time WebSocket buffer ---------------------------------
    event_buffer = EventBuffer(max_per_org=100)

    # ------------------------------------------------------------------
    # Drive 6 requests through the entire stack.
    # ------------------------------------------------------------------
    rate_limited = 0
    license_blocked = 0
    successful_runs: list[str] = []

    for i in range(6):
        # 1. Rate limit
        allowed, _retry = await rate_limiter.try_consume(org_id)
        if not allowed:
            rate_limited += 1
            continue

        # 2. License gate — try to start a new agent
        agent_name = f"agent-{i}"
        try:
            guard.check_can_start(agent_name)
        except LicenseExceededError:
            license_blocked += 1
            await audit_repo.append(
                org_id=org_id,
                action="license.start_blocked",
                actor=agent_name,
                target="agent.start",
                result="denied",
            )
            event_buffer.append(org_id, {"type": "agent_blocked", "agent": agent_name})
            continue

        # 3. Mark started in registry — feeds back into the counter callback
        registry.set_status(agent_name, "started")

        # 4. Audit + event for the successful start
        await audit_repo.append(
            org_id=org_id,
            action="agent.started",
            actor=agent_name,
            target="agent.start",
            result="ok",
        )
        event_buffer.append(org_id, {"type": "agent_started", "agent": agent_name})
        successful_runs.append(agent_name)

    # --------------- Assertions ----------------------------------------------
    # Bucket = 5, so the 6th request is rate-limited.
    assert rate_limited == 1

    # 5 requests passed rate-limit. License limit = 2 → first 2 succeed,
    # remaining 3 hit the LicenseExceededError branch.
    assert len(successful_runs) == 2
    assert license_blocked == 3

    # Audit log: 2 successes + 3 license-blocked = 5 entries.
    rows, total = await audit_repo.list_entries(org_id)
    assert total == 5
    actions = sorted(r.action for r in rows)
    assert actions == [
        "agent.started",
        "agent.started",
        "license.start_blocked",
        "license.start_blocked",
        "license.start_blocked",
    ]

    # Tenant isolation on cursor pagination — must only see this org.
    page, _cursor = await audit_repo.list_entries_cursor(org_id, limit=10)
    assert all(r.org_id == org_id for r in page)

    # WebSocket buffer received an event per non-rate-limited request.
    events = event_buffer.replay_since(org_id, since_id=None)
    assert len(events) == 5
    types = [e["data"]["type"] for e in events]
    assert types.count("agent_started") == 2
    assert types.count("agent_blocked") == 3

    # Replay-since: dropping the first ID should yield 4 events.
    first_id = events[0]["id"]
    tail = event_buffer.replay_since(org_id, since_id=first_id)
    assert len(tail) == 4

    # And the registry counter (which the LicenseGuard called) saw both
    # started agents.
    assert guard.current_agent_count() == 2
