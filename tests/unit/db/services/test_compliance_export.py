"""Contract tests for ComplianceExportService — RFC #245 PR-4 / #273."""

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
    from shieldops.db.services import compliance_export as mod

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
    from shieldops.db.services.compliance_export import ComplianceExportService

    return ComplianceExportService(session_factory)


class TestConstruction:
    def test_constructor_holds_session_factory(self, session_factory) -> None:
        from shieldops.db.services.compliance_export import ComplianceExportService

        svc = ComplianceExportService(session_factory)
        assert svc._sf is session_factory


class TestExportBundle:
    @pytest.mark.asyncio
    async def test_empty_bundle_when_no_data(self, service) -> None:
        bundle = await service.export_bundle(period_days=7)
        assert bundle["totals"] == {
            "investigations": 0,
            "remediations": 0,
            "audit": 0,
        }
        assert bundle["investigations"] == []
        assert bundle["period_days"] == 7
        assert "generated_at" in bundle

    @pytest.mark.asyncio
    async def test_bundle_includes_recent_rows(self, service, session_factory) -> None:
        async with session_factory() as session:
            session.add(FakeInvestigation(id="i-1", alert_id="a", alert_name="x", severity="high"))
            session.add(
                FakeRemediation(
                    id="r-1",
                    action_type="patch",
                    target_resource="srv",
                    environment="prod",
                    risk_level="medium",
                    status="success",
                )
            )
            session.add(
                FakeAuditLog(
                    id="aud-x",
                    action="approve",
                    actor="user:alice",
                    environment="prod",
                    outcome="success",
                )
            )
            await session.commit()

        bundle = await service.export_bundle(period_days=30)
        assert bundle["totals"]["investigations"] == 1
        assert bundle["totals"]["remediations"] == 1
        assert bundle["totals"]["audit"] == 1
        assert bundle["investigations"][0]["id"] == "i-1"

    @pytest.mark.asyncio
    async def test_bundle_excludes_old_rows(self, service, session_factory) -> None:
        old = datetime.now(UTC) - timedelta(days=90)
        async with session_factory() as session:
            session.add(
                FakeInvestigation(
                    id="i-old",
                    alert_id="a",
                    alert_name="x",
                    severity="low",
                    created_at=old,
                )
            )
            await session.commit()

        bundle = await service.export_bundle(period_days=7)
        assert bundle["totals"]["investigations"] == 0

    @pytest.mark.asyncio
    async def test_environment_filter(self, service, session_factory) -> None:
        async with session_factory() as session:
            session.add(
                FakeRemediation(
                    id="r-prod",
                    action_type="x",
                    target_resource="t",
                    environment="prod",
                    risk_level="low",
                    status="success",
                )
            )
            session.add(
                FakeRemediation(
                    id="r-dev",
                    action_type="x",
                    target_resource="t",
                    environment="dev",
                    risk_level="low",
                    status="success",
                )
            )
            await session.commit()

        bundle = await service.export_bundle(period_days=30, environment="prod")
        rem_ids = [r["id"] for r in bundle["remediations"]]
        assert rem_ids == ["r-prod"]


class TestSummaryCounts:
    @pytest.mark.asyncio
    async def test_returns_only_totals(self, service, session_factory) -> None:
        async with session_factory() as session:
            session.add(FakeInvestigation(id="i", alert_id="a", alert_name="x", severity="low"))
            await session.commit()

        counts = await service.summary_counts(period_days=30)
        assert counts == {"investigations": 1, "remediations": 0, "audit": 0}
