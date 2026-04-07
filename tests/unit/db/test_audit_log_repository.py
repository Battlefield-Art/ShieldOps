"""Unified audit log repository — TDD tests (#6-unified)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import JSON, DateTime, String
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from shieldops.db.repositories.audit_log import AuditLogRepository


class _TestBase(DeclarativeBase):
    pass


class _TestAuditLogRecord(_TestBase):
    __tablename__ = "audit_log_test"
    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: f"al-{uuid4().hex[:12]}"
    )
    org_id: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(128), index=True)
    actor: Mapped[str] = mapped_column(String(128), default="")
    target: Mapped[str] = mapped_column(String(256), default="")
    result: Mapped[str] = mapped_column(String(32), default="")
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
    )


@pytest_asyncio.fixture()
async def session(monkeypatch: pytest.MonkeyPatch) -> AsyncSession:
    from shieldops.db.repositories import audit_log as mod

    monkeypatch.setattr(mod, "AuditLogRecord", _TestAuditLogRecord)

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(_TestBase.metadata.create_all)
    async_session = async_sessionmaker(engine, expire_on_commit=False)
    async with async_session() as s:
        yield s
    await engine.dispose()


@pytest_asyncio.fixture()
async def repo(session: AsyncSession) -> AuditLogRepository:
    return AuditLogRepository(session)


class TestAuditLogAppend:
    @pytest.mark.asyncio
    async def test_append_persists_entry(self, repo: AuditLogRepository) -> None:
        entry = await repo.append(
            org_id="org-a",
            action="firewall.evaluate",
            actor="agent:investigation",
            target="tool:read_logs",
            result="allow",
            metadata={"risk_score": 0.1},
        )
        assert entry.id.startswith("al-")
        rows, total = await repo.list_entries("org-a")
        assert total == 1
        assert rows[0].action == "firewall.evaluate"

    @pytest.mark.asyncio
    async def test_tenant_isolation(self, repo: AuditLogRepository) -> None:
        await repo.append(org_id="org-a", action="a", actor="u", target="t", result="ok")
        await repo.append(org_id="org-b", action="b", actor="u", target="t", result="ok")
        a_rows, a_total = await repo.list_entries("org-a")
        b_rows, b_total = await repo.list_entries("org-b")
        assert a_total == 1 and a_rows[0].action == "a"
        assert b_total == 1 and b_rows[0].action == "b"


class TestAuditLogFilter:
    @pytest.mark.asyncio
    async def test_filter_by_action(self, repo: AuditLogRepository) -> None:
        await repo.append(org_id="org-a", action="login", actor="u1", target="", result="ok")
        await repo.append(org_id="org-a", action="logout", actor="u1", target="", result="ok")
        await repo.append(org_id="org-a", action="login", actor="u2", target="", result="ok")
        rows, total = await repo.list_entries("org-a", action="login")
        assert total == 2
        assert all(r.action == "login" for r in rows)

    @pytest.mark.asyncio
    async def test_filter_by_actor(self, repo: AuditLogRepository) -> None:
        await repo.append(org_id="org-a", action="x", actor="alice", target="", result="ok")
        await repo.append(org_id="org-a", action="x", actor="bob", target="", result="ok")
        rows, total = await repo.list_entries("org-a", actor="alice")
        assert total == 1
        assert rows[0].actor == "alice"

    @pytest.mark.asyncio
    async def test_pagination_newest_first(self, repo: AuditLogRepository) -> None:
        for i in range(5):
            await repo.append(
                org_id="org-a",
                action=f"a{i}",
                actor="u",
                target="",
                result="ok",
            )
        page1, total = await repo.list_entries("org-a", limit=2, offset=0)
        page2, _ = await repo.list_entries("org-a", limit=2, offset=2)
        assert total == 5
        assert len(page1) == 2 and len(page2) == 2
        # Newest first
        assert page1[0].action == "a4"
        assert page1[1].action == "a3"


class TestAuditLogDateFilter:
    @pytest.mark.asyncio
    async def test_filter_by_date_range(
        self, repo: AuditLogRepository, session: AsyncSession
    ) -> None:
        # Manually insert with custom created_at
        now = datetime.now(UTC)
        old = _TestAuditLogRecord(
            org_id="org-a",
            action="old",
            actor="",
            target="",
            result="ok",
            created_at=now - timedelta(days=10),
        )
        recent = _TestAuditLogRecord(
            org_id="org-a",
            action="recent",
            actor="",
            target="",
            result="ok",
            created_at=now - timedelta(hours=1),
        )
        session.add_all([old, recent])
        await session.commit()

        cutoff = now - timedelta(days=5)
        rows, total = await repo.list_entries("org-a", since=cutoff)
        assert total == 1
        assert rows[0].action == "recent"


class TestAuditLogCursorPagination:
    """Keyset cursor pagination — TDD #3 (Round 3)."""

    @pytest.mark.asyncio
    async def test_first_page_returns_newest_first_with_cursor(
        self, repo: AuditLogRepository
    ) -> None:
        for i in range(5):
            await repo.append(org_id="org-a", action=f"a{i}", actor="u", target="", result="ok")
        rows, cursor = await repo.list_entries_cursor("org-a", limit=2)
        assert len(rows) == 2
        assert rows[0].action == "a4"
        assert rows[1].action == "a3"
        assert cursor is not None

    @pytest.mark.asyncio
    async def test_second_page_continues_from_cursor(self, repo: AuditLogRepository) -> None:
        for i in range(5):
            await repo.append(org_id="org-a", action=f"a{i}", actor="u", target="", result="ok")
        page1, cursor1 = await repo.list_entries_cursor("org-a", limit=2)
        page2, cursor2 = await repo.list_entries_cursor("org-a", limit=2, after_cursor=cursor1)
        assert [r.action for r in page2] == ["a2", "a1"]
        assert cursor2 is not None

    @pytest.mark.asyncio
    async def test_exhausted_pages_return_none_cursor(self, repo: AuditLogRepository) -> None:
        for i in range(3):
            await repo.append(org_id="org-a", action=f"a{i}", actor="u", target="", result="ok")
        rows, cursor = await repo.list_entries_cursor("org-a", limit=10)
        assert len(rows) == 3
        assert cursor is None

    @pytest.mark.asyncio
    async def test_cursor_preserves_tenant_isolation(self, repo: AuditLogRepository) -> None:
        for i in range(3):
            await repo.append(org_id="org-a", action=f"a{i}", actor="u", target="", result="ok")
            await repo.append(org_id="org-b", action=f"b{i}", actor="u", target="", result="ok")
        rows_a, cursor_a = await repo.list_entries_cursor("org-a", limit=2)
        rows_b, _ = await repo.list_entries_cursor("org-b", limit=2, after_cursor=cursor_a)
        assert all(r.org_id == "org-a" for r in rows_a)
        # Cursor from org-a must NOT leak rows from org-b's perspective
        assert all(r.org_id == "org-b" for r in rows_b)
        assert {r.action for r in rows_b}.issubset({"b0", "b1", "b2"})

    @pytest.mark.asyncio
    async def test_invalid_cursor_raises_value_error(self, repo: AuditLogRepository) -> None:
        with pytest.raises(ValueError, match="cursor"):
            await repo.list_entries_cursor("org-a", after_cursor="not-a-real-cursor")
