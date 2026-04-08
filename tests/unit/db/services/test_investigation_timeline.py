"""Contract tests for InvestigationTimelineService — RFC #245 PR-4 / #273."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from tests.unit.db.services.conftest import (
    FakeAuditLog,
    FakeInvestigation,
    FakeRemediation,
    SvcBase,
)


@pytest_asyncio.fixture()
async def session_factory(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[async_sessionmaker]:
    from shieldops.db.services import investigation_timeline as mod

    monkeypatch.setattr(mod, "InvestigationRecord", FakeInvestigation)
    monkeypatch.setattr(mod, "RemediationRecord", FakeRemediation)
    monkeypatch.setattr(mod, "AuditLog", FakeAuditLog)

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(SvcBase.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    yield sf
    await engine.dispose()


@pytest_asyncio.fixture()
async def service(session_factory: async_sessionmaker):
    from shieldops.db.services.investigation_timeline import InvestigationTimelineService

    return InvestigationTimelineService(session_factory)


class TestConstruction:
    def test_constructor_takes_session_factory(self, session_factory) -> None:
        from shieldops.db.services.investigation_timeline import (
            InvestigationTimelineService,
        )

        svc = InvestigationTimelineService(session_factory)
        assert svc._sf is session_factory


class TestBuildTimeline:
    @pytest.mark.asyncio
    async def test_returns_empty_when_investigation_missing(self, service) -> None:
        events = await service.build_timeline("inv-missing")
        assert events == []

    @pytest.mark.asyncio
    async def test_merges_investigation_remediation_audit(self, service, session_factory) -> None:
        now = datetime.now(UTC)
        async with session_factory() as session:
            session.add(
                FakeInvestigation(
                    id="inv-1",
                    alert_id="a-1",
                    alert_name="cpu",
                    severity="warning",
                    status="completed",
                    created_at=now - timedelta(minutes=5),
                    updated_at=now - timedelta(minutes=5),
                )
            )
            session.add(
                FakeRemediation(
                    id="rem-1",
                    action_type="restart",
                    target_resource="pod-x",
                    environment="prod",
                    risk_level="low",
                    status="success",
                    investigation_id="inv-1",
                    created_at=now - timedelta(minutes=4),
                )
            )
            session.add(
                FakeAuditLog(
                    id="aud-1",
                    timestamp=now - timedelta(minutes=3),
                    agent_type="investigation",
                    action="logged",
                    target_resource="a-1",
                    environment="prod",
                    risk_level="warning",
                    policy_evaluation="allowed",
                    outcome="success",
                    reasoning="trace inv-1",
                    actor="agent:investigation",
                )
            )
            await session.commit()

        events = await service.build_timeline("inv-1")
        types = [e["type"] for e in events]
        assert "investigation" in types
        assert "remediation" in types
        assert "audit" in types
        # chronological order
        timestamps = [e["timestamp"] for e in events if e["timestamp"]]
        assert timestamps == sorted(timestamps)

    @pytest.mark.asyncio
    async def test_filter_by_type(self, service, session_factory) -> None:
        async with session_factory() as session:
            session.add(
                FakeInvestigation(id="inv-2", alert_id="a-2", alert_name="x", severity="info")
            )
            session.add(
                FakeRemediation(
                    id="rem-2",
                    action_type="patch",
                    target_resource="r",
                    environment="dev",
                    risk_level="low",
                    status="success",
                    investigation_id="inv-2",
                )
            )
            await session.commit()

        only_rem = await service.filter_by_type("inv-2", "remediation")
        assert all(e["type"] == "remediation" for e in only_rem)
        assert len(only_rem) == 1

    @pytest.mark.asyncio
    async def test_count_events(self, service, session_factory) -> None:
        ts = datetime.now(UTC)
        async with session_factory() as session:
            session.add(
                FakeInvestigation(
                    id="inv-3",
                    alert_id="a-3",
                    alert_name="y",
                    severity="warning",
                    created_at=ts,
                    updated_at=ts,  # equal -> no "updated" duplicate event
                )
            )
            await session.commit()

        assert await service.count_events("inv-3") == 1
        assert await service.count_events("inv-missing") == 0
