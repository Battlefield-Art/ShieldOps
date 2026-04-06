"""NL Query audit DB persistence — TDD tests (#5)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import Boolean, Float, Integer, String, Text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from shieldops.db.repositories.nl_query_audit import NLQueryAuditRepository


class _TestBase(DeclarativeBase):
    pass


class _TestNLQueryAuditRecord(_TestBase):
    __tablename__ = "nl_query_audit_test"
    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: f"nlq-{uuid4().hex[:12]}"
    )
    org_id: Mapped[str] = mapped_column(String(64), index=True)
    user_id: Mapped[str] = mapped_column(String(64), default="")
    question: Mapped[str] = mapped_column(Text)
    generated_sql: Mapped[str] = mapped_column(Text, default="")
    result_count: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    cache_hit: Mapped[bool] = mapped_column(Boolean, default=False)
    source: Mapped[str] = mapped_column(String(32), default="llm")
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(UTC))


@pytest_asyncio.fixture()
async def session(monkeypatch: pytest.MonkeyPatch) -> AsyncSession:
    from shieldops.db.repositories import nl_query_audit as audit_mod

    monkeypatch.setattr(audit_mod, "NLQueryAuditRecord", _TestNLQueryAuditRecord)

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(_TestBase.metadata.create_all)
    async_session = async_sessionmaker(engine, expire_on_commit=False)
    async with async_session() as s:
        yield s
    await engine.dispose()


@pytest_asyncio.fixture()
async def repo(session: AsyncSession) -> NLQueryAuditRepository:
    return NLQueryAuditRepository(session)


class TestNLQueryAuditRepository:
    @pytest.mark.asyncio
    async def test_list_empty_returns_empty(self, repo: NLQueryAuditRepository) -> None:
        rows, total = await repo.list_queries("org-a")
        assert rows == []
        assert total == 0

    @pytest.mark.asyncio
    async def test_log_query_persists_record(self, repo: NLQueryAuditRepository) -> None:
        record = await repo.log_query(
            org_id="org-a",
            user_id="user-1",
            question="show critical alerts",
            generated_sql="SELECT * FROM events WHERE severity='critical'",
            result_count=5,
            latency_ms=42.5,
        )
        assert record.id.startswith("nlq-")
        rows, total = await repo.list_queries("org-a")
        assert total == 1
        assert rows[0].question == "show critical alerts"
        assert rows[0].result_count == 5
        assert rows[0].cache_hit is False
        assert rows[0].source == "llm"

    @pytest.mark.asyncio
    async def test_tenant_isolation(self, repo: NLQueryAuditRepository) -> None:
        await repo.log_query(
            org_id="org-a",
            user_id="u",
            question="q1",
            generated_sql="SELECT 1",
            result_count=1,
            latency_ms=1,
        )
        await repo.log_query(
            org_id="org-b",
            user_id="u",
            question="q2",
            generated_sql="SELECT 2",
            result_count=2,
            latency_ms=2,
        )
        a_rows, a_total = await repo.list_queries("org-a")
        b_rows, b_total = await repo.list_queries("org-b")
        assert a_total == 1 and a_rows[0].question == "q1"
        assert b_total == 1 and b_rows[0].question == "q2"

    @pytest.mark.asyncio
    async def test_pagination_newest_first(self, repo: NLQueryAuditRepository) -> None:
        for i in range(5):
            await repo.log_query(
                org_id="org-c",
                user_id="u",
                question=f"q{i}",
                generated_sql="SELECT 1",
                result_count=0,
                latency_ms=1,
            )
        page1, total = await repo.list_queries("org-c", limit=2, offset=0)
        page2, _ = await repo.list_queries("org-c", limit=2, offset=2)
        assert total == 5
        assert len(page1) == 2
        assert len(page2) == 2
        # Newest first: q4 then q3 on page 1
        assert page1[0].question == "q4"
        assert page1[1].question == "q3"

    @pytest.mark.asyncio
    async def test_cache_hit_is_recorded(self, repo: NLQueryAuditRepository) -> None:
        await repo.log_query(
            org_id="org-d",
            user_id="u",
            question="cached",
            generated_sql="SELECT 1",
            result_count=1,
            latency_ms=1,
            cache_hit=True,
            source="cache",
        )
        rows, _ = await repo.list_queries("org-d")
        assert rows[0].cache_hit is True
        assert rows[0].source == "cache"
