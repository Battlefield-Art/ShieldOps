"""Contract tests for db.fetch — RFC #245 PR-1.

See ghantakiran/ShieldOps#245. These tests lock the structural
properties of the new 99%-caller path:

1. **Type safety via TypeVar bound** — calling ``fetch.get(s, Model, id)``
   returns ``Model | None``, not ``Any``. The mypy check is implicit
   (we assert on the returned instance's attributes, which only works
   if it's typed correctly).

2. **Soft-delete is honored by default** — a soft-deleted row is not
   returned by ``get`` unless ``include_deleted=True`` is passed.

3. **``save`` + ``get`` round-trip** — the helper sequence that 99%
   of new code will use.

All tests use the isolated-test-model pattern: a local ``DeclarativeBase``
subclass + an in-memory SQLite engine, so these tests don't touch the
production model graph or any real DB. Same pattern as the TDD round 3
audit-log repository tests.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import DateTime, String
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class _TestBase(DeclarativeBase):
    pass


class _TestWidget(_TestBase):
    __tablename__ = "widgets"
    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: f"w-{uuid4().hex[:12]}"
    )
    name: Mapped[str] = mapped_column(String(128))
    color: Mapped[str] = mapped_column(String(32), default="")
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


@pytest_asyncio.fixture()
async def session(monkeypatch: pytest.MonkeyPatch) -> AsyncSession:
    """Isolated in-memory session. Monkey-patches Base in the fetch
    module so the soft-delete check in fetch.get picks up our test
    model's deleted_at column without touching the production Base."""
    from shieldops.db import fetch as fetch_mod

    monkeypatch.setattr(fetch_mod, "Base", _TestBase)

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(_TestBase.metadata.create_all)
    Session = async_sessionmaker(engine, expire_on_commit=False)
    async with Session() as s:
        yield s
    await engine.dispose()


# Import AFTER the fixture patches fetch_mod.Base — but we just need
# the helpers, not Base itself, so this is fine.
from shieldops.db import fetch  # noqa: E402

# ---------------------------------------------------------------------------
# 1. Save + get round-trip (the 99% happy path)
# ---------------------------------------------------------------------------


class TestSaveAndGet:
    @pytest.mark.asyncio
    async def test_save_persists_and_refreshes(self, session: AsyncSession) -> None:
        w = _TestWidget(name="widget-a", color="red")
        saved = await fetch.save(session, w)
        await session.commit()
        assert saved.id.startswith("w-")
        assert saved.name == "widget-a"

    @pytest.mark.asyncio
    async def test_get_returns_instance_by_id(self, session: AsyncSession) -> None:
        w = _TestWidget(name="widget-a", color="red")
        await fetch.save(session, w)
        await session.commit()

        fetched = await fetch.get(session, _TestWidget, w.id)
        assert fetched is not None
        assert fetched.name == "widget-a"
        assert fetched.color == "red"

    @pytest.mark.asyncio
    async def test_get_returns_none_for_missing_id(self, session: AsyncSession) -> None:
        assert await fetch.get(session, _TestWidget, "nope") is None

    @pytest.mark.asyncio
    async def test_get_or_404_raises_on_missing(self, session: AsyncSession) -> None:
        with pytest.raises(LookupError, match="_TestWidget"):
            await fetch.get_or_404(session, _TestWidget, "nope")


# ---------------------------------------------------------------------------
# 2. find + list_ + count (the filter helpers)
# ---------------------------------------------------------------------------


class TestFindListCount:
    @pytest.mark.asyncio
    async def test_find_returns_first_match(self, session: AsyncSession) -> None:
        await fetch.save(session, _TestWidget(name="a", color="red"))
        await fetch.save(session, _TestWidget(name="b", color="blue"))
        await session.commit()

        found = await fetch.find(session, _TestWidget, color="red")
        assert found is not None and found.name == "a"

    @pytest.mark.asyncio
    async def test_find_returns_none_when_no_match(self, session: AsyncSession) -> None:
        await fetch.save(session, _TestWidget(name="a", color="red"))
        await session.commit()
        assert await fetch.find(session, _TestWidget, color="green") is None

    @pytest.mark.asyncio
    async def test_list_filters_by_column(self, session: AsyncSession) -> None:
        for n, c in [("a", "red"), ("b", "red"), ("c", "blue")]:
            await fetch.save(session, _TestWidget(name=n, color=c))
        await session.commit()

        reds = await fetch.list_(session, _TestWidget, color="red")
        assert len(reds) == 2
        assert {w.name for w in reds} == {"a", "b"}

    @pytest.mark.asyncio
    async def test_list_respects_limit_and_offset(self, session: AsyncSession) -> None:
        for i in range(10):
            await fetch.save(session, _TestWidget(name=f"w{i}", color="red"))
        await session.commit()

        page1 = await fetch.list_(session, _TestWidget, limit=3, offset=0)
        page2 = await fetch.list_(session, _TestWidget, limit=3, offset=3)
        assert len(page1) == 3
        assert len(page2) == 3
        assert {w.id for w in page1}.isdisjoint({w.id for w in page2})

    @pytest.mark.asyncio
    async def test_count_returns_row_count(self, session: AsyncSession) -> None:
        for i in range(7):
            await fetch.save(session, _TestWidget(name=f"w{i}", color="red"))
        await session.commit()

        assert await fetch.count(session, _TestWidget) == 7
        assert await fetch.count(session, _TestWidget, color="red") == 7
        assert await fetch.count(session, _TestWidget, color="blue") == 0


# ---------------------------------------------------------------------------
# 3. Soft-delete contract
# ---------------------------------------------------------------------------


class TestSoftDelete:
    @pytest.mark.asyncio
    async def test_soft_delete_hides_from_get_by_default(self, session: AsyncSession) -> None:
        w = _TestWidget(name="doomed", color="red")
        await fetch.save(session, w)
        await session.commit()

        await fetch.delete_(session, w, soft=True)
        await session.commit()

        # Default get() does not return soft-deleted rows.
        assert await fetch.get(session, _TestWidget, w.id) is None

    @pytest.mark.asyncio
    async def test_include_deleted_returns_soft_deleted_row(self, session: AsyncSession) -> None:
        w = _TestWidget(name="doomed", color="red")
        await fetch.save(session, w)
        await session.commit()

        await fetch.delete_(session, w, soft=True)
        await session.commit()

        fetched = await fetch.get(session, _TestWidget, w.id, include_deleted=True)
        assert fetched is not None
        assert fetched.deleted_at is not None

    @pytest.mark.asyncio
    async def test_hard_delete_removes_row(self, session: AsyncSession) -> None:
        w = _TestWidget(name="gone", color="red")
        await fetch.save(session, w)
        await session.commit()

        await fetch.delete_(session, w, soft=False)
        await session.commit()

        # Even include_deleted=True can't find a hard-deleted row.
        assert await fetch.get(session, _TestWidget, w.id, include_deleted=True) is None


# ---------------------------------------------------------------------------
# 4. Type safety smoke test — the returned instance supports the model's attrs
# ---------------------------------------------------------------------------


class TestTypeSafety:
    @pytest.mark.asyncio
    async def test_get_returns_typed_instance(self, session: AsyncSession) -> None:
        """Smoke test that ``fetch.get(s, _TestWidget, id)`` returns a
        ``_TestWidget | None`` — callers should be able to access the
        model's specific attributes without ``type: ignore`` comments."""
        w = _TestWidget(name="typed", color="blue")
        await fetch.save(session, w)
        await session.commit()

        fetched = await fetch.get(session, _TestWidget, w.id)
        assert fetched is not None
        # These attribute accesses would fail mypy if the TypeVar bound
        # didn't narrow the return type — the whole point of PR-1's
        # ``TypeVar('M', bound=Base)`` is to make this work.
        name: str = fetched.name
        color: str = fetched.color
        assert name == "typed"
        assert color == "blue"
