"""Stateless fetch helpers — the 99% DB call path (RFC #245 PR-1).

See ghantakiran/ShieldOps#245. These functions replace per-entity
repository classes for the 99% call pattern ("fetch one entity by id
or filter"). They are:

- **Stateless** — no classes to construct, no ``session_factory``
  injection, no ``app.state.repository`` singleton.
- **Typed** — ``TypeVar``-bound generics so ``fetch.get(s, Investigation, id)``
  has return type ``Investigation | None`` rather than ``Any``.
- **Session-in, entity-out** — callers pass an existing ``AsyncSession``
  (via FastAPI ``Depends(get_session)``), not a repo.

The 1% case — cross-entity joins, transactional multi-entity writes,
export aggregations — lives in ``db/services/*.py`` as named service
classes (each with ≤5 public methods).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shieldops.db.models import Base

# ---------------------------------------------------------------------------
# The 7 stateless helpers
#
# NOTE: we use PEP 695 type parameters (`def get[M: Base](...)`) rather
# than a module-level `TypeVar`. This is required by ruff rule UP047
# and by RFC #245's acceptance criterion: mypy must narrow the return
# type of `fetch.get(session, Investigation, id)` to `Investigation | None`
# without any explicit `TypeVar` sticking around in the module.
# ---------------------------------------------------------------------------


async def get[M: Base](
    session: AsyncSession,
    model: type[M],
    id: Any,
    *,
    include_deleted: bool = False,
) -> M | None:
    """Fetch a row by primary key. Returns ``None`` if not found.

    Respects soft-delete via the ``deleted_at`` column if present, unless
    ``include_deleted=True`` is passed. Tenant scoping is left to the
    caller (pass ``tenant_id=`` to :func:`find` for that).
    """
    instance = await session.get(model, id)
    if instance is None:
        return None
    if not include_deleted and _is_soft_deleted(instance):
        return None
    return instance


async def get_or_404[M: Base](
    session: AsyncSession,
    model: type[M],
    id: Any,
) -> M:
    """Like :func:`get` but raises :class:`LookupError` if missing.

    Callers wrap this in FastAPI ``HTTPException(404)`` at the route
    layer if they need an HTTP status code.
    """
    instance = await get(session, model, id)
    if instance is None:
        raise LookupError(f"{model.__name__}({id!r}) not found")
    return instance


async def find[M: Base](
    session: AsyncSession,
    model: type[M],
    /,
    **filters: Any,
) -> M | None:
    """Return the first row matching the given column filters, or ``None``."""
    stmt = select(model).filter_by(**filters).limit(1)
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def list_[M: Base](
    session: AsyncSession,
    model: type[M],
    /,
    *,
    limit: int = 50,
    offset: int = 0,
    order_by: str | None = None,
    **filters: Any,
) -> list[M]:
    """Return a list of rows matching the filters, newest-first by default."""
    stmt = select(model).filter_by(**filters)
    if order_by is not None:
        col = getattr(model, order_by, None)
        if col is not None:
            stmt = stmt.order_by(col.desc())
    elif hasattr(model, "created_at"):
        stmt = stmt.order_by(model.created_at.desc())
    stmt = stmt.limit(limit).offset(offset)
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def count[M: Base](
    session: AsyncSession,
    model: type[M],
    /,
    **filters: Any,
) -> int:
    """Count rows matching the filters."""
    stmt = select(func.count()).select_from(model).filter_by(**filters)
    result = await session.execute(stmt)
    return int(result.scalar_one())


async def save[M: Base](
    session: AsyncSession,
    instance: M,
) -> M:
    """Add an instance, flush to get the PK, refresh. Caller still commits."""
    session.add(instance)
    await session.flush()
    await session.refresh(instance)
    return instance


async def delete_[M: Base](
    session: AsyncSession,
    instance: M,
    *,
    soft: bool = True,
) -> None:
    """Delete an instance. Soft-delete by default if the model supports it."""
    if soft and hasattr(instance, "deleted_at"):
        from datetime import UTC, datetime

        instance.deleted_at = datetime.now(UTC)  # type: ignore[attr-defined]
        session.add(instance)
        await session.flush()
        return
    await session.delete(instance)
    await session.flush()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_soft_deleted(instance: Any) -> bool:
    deleted_at = getattr(instance, "deleted_at", None)
    return deleted_at is not None
