"""Contract tests for InvestigationWriteService — RFC #245 PR-4 / #273."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from tests.unit.db.services.conftest import (
    FakeAuditLog,
    FakeInvestigation,
    SvcBase,
)


@pytest_asyncio.fixture()
async def session_factory(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[async_sessionmaker]:
    from shieldops.db.services import investigation_write as mod

    monkeypatch.setattr(mod, "InvestigationRecord", FakeInvestigation)
    monkeypatch.setattr(mod, "AuditLog", FakeAuditLog)

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(SvcBase.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    yield sf
    await engine.dispose()


@pytest_asyncio.fixture()
async def service(session_factory: async_sessionmaker):
    from shieldops.db.services.investigation_write import InvestigationWriteService

    return InvestigationWriteService(session_factory)


class TestConstruction:
    def test_constructor_holds_session_factory(self, session_factory) -> None:
        from shieldops.db.services.investigation_write import InvestigationWriteService

        svc = InvestigationWriteService(session_factory)
        assert svc._sf is session_factory


class TestCreateWithAudit:
    @pytest.mark.asyncio
    async def test_creates_investigation_and_audit_atomically(
        self, service, session_factory
    ) -> None:
        result = await service.create_with_audit(
            investigation_id="inv-1",
            alert_id="alert-1",
            alert_name="cpu spike",
            severity="warning",
            reasoning="initial trigger",
        )
        assert result["id"] == "inv-1"
        assert result["alert_id"] == "alert-1"

        async with session_factory() as session:
            invs = (await session.execute(select(FakeInvestigation))).scalars().all()
            audits = (await session.execute(select(FakeAuditLog))).scalars().all()
        assert len(invs) == 1
        assert len(audits) == 1
        assert audits[0].action == "investigation_created"
        assert audits[0].agent_type == "investigation"

    @pytest.mark.asyncio
    async def test_existing_investigation_appends_only_audit(
        self, service, session_factory
    ) -> None:
        await service.create_with_audit(
            investigation_id="inv-2",
            alert_id="a",
            alert_name="x",
        )
        await service.create_with_audit(
            investigation_id="inv-2",
            alert_id="a",
            alert_name="x",
        )

        async with session_factory() as session:
            invs = (await session.execute(select(FakeInvestigation))).scalars().all()
            audits = (await session.execute(select(FakeAuditLog))).scalars().all()
        assert len(invs) == 1  # not duplicated
        assert len(audits) == 2  # audit log is append-only


class TestUpdateStatus:
    @pytest.mark.asyncio
    async def test_returns_false_for_missing_investigation(self, service) -> None:
        ok = await service.update_status("inv-missing", "completed")
        assert ok is False

    @pytest.mark.asyncio
    async def test_updates_status_and_writes_audit(self, service, session_factory) -> None:
        await service.create_with_audit(
            investigation_id="inv-3",
            alert_id="a-3",
            alert_name="x",
        )
        ok = await service.update_status("inv-3", "completed")
        assert ok is True

        async with session_factory() as session:
            inv = await session.get(FakeInvestigation, "inv-3")
            audits = (await session.execute(select(FakeAuditLog))).scalars().all()
        assert inv is not None
        assert inv.status == "completed"
        # 1 from create_with_audit + 1 from update_status
        assert len(audits) == 2
        assert any(a.action == "investigation_status_completed" for a in audits)
