"""Monthly token-usage reporter — TDD tests (#6 Round 3)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from shieldops.billing.monthly_usage_reporter import MonthlyUsageReporter


class _TestBase(DeclarativeBase):
    pass


class _TestAgentRun(_TestBase):
    __tablename__ = "agent_runs_test"
    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: f"run-{uuid4().hex[:12]}"
    )
    agent_name: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32), default="completed")
    org_id: Mapped[str] = mapped_column(String(64), index=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    token_usage: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


@pytest_asyncio.fixture()
async def session(monkeypatch: pytest.MonkeyPatch) -> AsyncSession:
    from shieldops.billing import monthly_usage_reporter as mod

    monkeypatch.setattr(mod, "AgentRun", _TestAgentRun)

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(_TestBase.metadata.create_all)
    Session = async_sessionmaker(engine, expire_on_commit=False)
    async with Session() as s:
        yield s
    await engine.dispose()


@pytest_asyncio.fixture()
async def reporter(session: AsyncSession) -> MonthlyUsageReporter:
    return MonthlyUsageReporter(session)


def _run(
    org_id: str,
    when: datetime,
    *,
    prompt: int = 100,
    completion: int = 50,
    duration_ms: int = 200,
    agent: str = "investigation",
) -> _TestAgentRun:
    return _TestAgentRun(
        agent_name=agent,
        org_id=org_id,
        duration_ms=duration_ms,
        created_at=when,
        token_usage={
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": prompt + completion,
        },
    )


class TestMonthlyUsageReporter:
    @pytest.mark.asyncio
    async def test_empty_month_returns_zero_totals(self, reporter: MonthlyUsageReporter) -> None:
        report = await reporter.compute(org_id="org-a", year=2026, month=4)
        assert report.org_id == "org-a"
        assert report.year == 2026 and report.month == 4
        assert report.total_runs == 0
        assert report.total_tokens == 0
        assert report.total_prompt_tokens == 0
        assert report.total_completion_tokens == 0
        assert report.runs_by_agent == {}

    @pytest.mark.asyncio
    async def test_sums_runs_within_month(
        self, reporter: MonthlyUsageReporter, session: AsyncSession
    ) -> None:
        session.add_all(
            [
                _run("org-a", datetime(2026, 4, 1, 10, 0, tzinfo=UTC), prompt=100, completion=50),
                _run("org-a", datetime(2026, 4, 15, 12, 0, tzinfo=UTC), prompt=200, completion=80),
                _run("org-a", datetime(2026, 4, 30, 23, 0, tzinfo=UTC), prompt=300, completion=70),
            ]
        )
        await session.commit()

        report = await reporter.compute(org_id="org-a", year=2026, month=4)
        assert report.total_runs == 3
        assert report.total_prompt_tokens == 600
        assert report.total_completion_tokens == 200
        assert report.total_tokens == 800

    @pytest.mark.asyncio
    async def test_excludes_other_months(
        self, reporter: MonthlyUsageReporter, session: AsyncSession
    ) -> None:
        session.add_all(
            [
                _run(
                    "org-a", datetime(2026, 3, 31, 23, 59, tzinfo=UTC), prompt=999, completion=999
                ),
                _run("org-a", datetime(2026, 5, 1, 0, 0, tzinfo=UTC), prompt=999, completion=999),
                _run("org-a", datetime(2026, 4, 10, 0, 0, tzinfo=UTC), prompt=10, completion=5),
            ]
        )
        await session.commit()

        report = await reporter.compute(org_id="org-a", year=2026, month=4)
        assert report.total_runs == 1
        assert report.total_tokens == 15

    @pytest.mark.asyncio
    async def test_excludes_other_orgs(
        self, reporter: MonthlyUsageReporter, session: AsyncSession
    ) -> None:
        session.add_all(
            [
                _run("org-a", datetime(2026, 4, 1, tzinfo=UTC), prompt=10, completion=5),
                _run("org-b", datetime(2026, 4, 1, tzinfo=UTC), prompt=999, completion=999),
            ]
        )
        await session.commit()
        report = await reporter.compute(org_id="org-a", year=2026, month=4)
        assert report.total_tokens == 15

    @pytest.mark.asyncio
    async def test_breakdown_by_agent(
        self, reporter: MonthlyUsageReporter, session: AsyncSession
    ) -> None:
        session.add_all(
            [
                _run("org-a", datetime(2026, 4, 1, tzinfo=UTC), agent="investigation"),
                _run("org-a", datetime(2026, 4, 2, tzinfo=UTC), agent="investigation"),
                _run("org-a", datetime(2026, 4, 3, tzinfo=UTC), agent="remediation"),
            ]
        )
        await session.commit()
        report = await reporter.compute(org_id="org-a", year=2026, month=4)
        assert report.runs_by_agent == {"investigation": 2, "remediation": 1}

    def test_invalid_month_raises(self, reporter: MonthlyUsageReporter) -> None:
        with pytest.raises(ValueError, match="month"):
            # compute() validates eagerly even before any DB access
            import asyncio

            asyncio.get_event_loop().run_until_complete(
                reporter.compute(org_id="org-a", year=2026, month=13)
            )
