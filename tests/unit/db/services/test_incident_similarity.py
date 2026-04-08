"""Contract tests for IncidentSimilarityService — RFC #245 PR-4 / #273."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from tests.unit.db.services.conftest import FakeIncidentOutcome, SvcBase


@pytest_asyncio.fixture()
async def session_factory(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[async_sessionmaker]:
    from shieldops.db.services import incident_similarity as mod

    monkeypatch.setattr(mod, "IncidentOutcomeRecord", FakeIncidentOutcome)

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(SvcBase.metadata.create_all)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    yield sf
    await engine.dispose()


@pytest_asyncio.fixture()
async def service(session_factory: async_sessionmaker):
    from shieldops.db.services.incident_similarity import IncidentSimilarityService

    return IncidentSimilarityService(session_factory)


async def _seed(session_factory, items: list[FakeIncidentOutcome]) -> None:
    async with session_factory() as session:
        for it in items:
            session.add(it)
        await session.commit()


class TestConstruction:
    def test_constructor_holds_session_factory(self, session_factory) -> None:
        from shieldops.db.services.incident_similarity import IncidentSimilarityService

        svc = IncidentSimilarityService(session_factory)
        assert svc._sf is session_factory


class TestFindSimilar:
    @pytest.mark.asyncio
    async def test_returns_empty_when_none_match(self, service) -> None:
        result = await service.find_similar("nonexistent_alert")
        assert result == []

    @pytest.mark.asyncio
    async def test_matches_alert_type_with_base_score(self, service, session_factory) -> None:
        await _seed(
            session_factory,
            [
                FakeIncidentOutcome(
                    id="i-1",
                    alert_type="cpu_spike",
                    environment="prod",
                    root_cause="bad query",
                ),
            ],
        )
        result = await service.find_similar("cpu_spike")
        assert len(result) == 1
        assert result[0]["similarity_score"] == 0.8
        assert result[0]["incident_id"] == "i-1"

    @pytest.mark.asyncio
    async def test_resource_id_bumps_score(self, service, session_factory) -> None:
        await _seed(
            session_factory,
            [
                FakeIncidentOutcome(
                    id="i-2",
                    alert_type="oom",
                    environment="prod",
                    root_cause="leak in pod-foo",
                ),
            ],
        )
        result = await service.find_similar("oom", resource_id="pod-foo")
        assert result[0]["similarity_score"] == 0.9

    @pytest.mark.asyncio
    async def test_environment_match_bumps_score(self, service, session_factory) -> None:
        await _seed(
            session_factory,
            [
                FakeIncidentOutcome(
                    id="i-3",
                    alert_type="oom",
                    environment="prod",
                    root_cause="leak in pod-foo",
                ),
            ],
        )
        result = await service.find_similar("oom", resource_id="pod-foo", environment="prod")
        assert result[0]["similarity_score"] == 0.95


class TestQueryRecent:
    @pytest.mark.asyncio
    async def test_filters_by_period(self, service, session_factory) -> None:
        old_ts = datetime.now(UTC) - timedelta(days=60)
        await _seed(
            session_factory,
            [
                FakeIncidentOutcome(
                    id="i-old", alert_type="x", environment="prod", created_at=old_ts
                ),
                FakeIncidentOutcome(id="i-new", alert_type="x", environment="prod"),
            ],
        )
        result = await service.query_recent(period="30d")
        ids = [o["incident_id"] for o in result["outcomes"]]
        assert "i-new" in ids
        assert "i-old" not in ids
        assert result["period"] == "30d"
        assert result["total_incidents"] == 1

    @pytest.mark.asyncio
    async def test_count_by_environment(self, service, session_factory) -> None:
        await _seed(
            session_factory,
            [
                FakeIncidentOutcome(id="a", alert_type="t", environment="prod"),
                FakeIncidentOutcome(id="b", alert_type="t", environment="prod"),
                FakeIncidentOutcome(id="c", alert_type="t", environment="staging"),
            ],
        )
        assert await service.count_by_environment("prod") == 2
        assert await service.count_by_environment("staging") == 1
        assert await service.count_by_environment("dev") == 0
