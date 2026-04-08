"""Named services for cross-entity DB queries — RFC #245 PR-4 (#273).

The 99% single-entity path lives in :mod:`shieldops.db.fetch` (PR-1).
This package holds the 1% of queries that span multiple tables —
joins, multi-table aggregates, compound reads/writes — as small,
named, independently-testable services.

Each service:

- Takes ``session_factory: async_sessionmaker[AsyncSession]`` in its
  constructor (no global state, no ``app.state.repository`` god object).
- Exposes ≤5 focused public methods.
- Lives in <200 LOC.
- Has its own contract test under ``tests/unit/db/services/``.

FastAPI integration uses :func:`get_service` for DI:

    from shieldops.db.services import get_service
    from shieldops.db.services.investigation_timeline import InvestigationTimelineService

    @router.get("/investigations/{id}/timeline")
    async def timeline(
        id: str,
        svc: InvestigationTimelineService = Depends(
            get_service(InvestigationTimelineService),
        ),
    ): ...

The factory reads ``app.state.session_factory`` (set in
``api.app`` lifespan) and constructs the service per-request.
Services are cheap — no per-request caching needed.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from fastapi import HTTPException, Request, status

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shieldops.db.services.compliance_export import ComplianceExportService
from shieldops.db.services.incident_similarity import IncidentSimilarityService
from shieldops.db.services.investigation_timeline import InvestigationTimelineService
from shieldops.db.services.investigation_write import InvestigationWriteService
from shieldops.db.services.onboarding_progress import OnboardingProgressService

# Cache the generated dependency per service class so callers that want
# to use FastAPI ``app.dependency_overrides[get_service(Foo)] = ...``
# get a stable callable identity. Without caching, every call to
# ``get_service(Foo)`` would return a fresh function and overrides
# would silently miss.
_DEP_CACHE: dict[type, Callable[[Request], object]] = {}


def get_service[S](service_cls: type[S]) -> Callable[[Request], S]:
    """Build (and cache) a FastAPI dependency that constructs ``service_cls``.

    The dependency reads ``request.app.state.session_factory`` and
    passes it to the service constructor. Raises ``503`` if the
    session factory hasn't been wired (DB unavailable).

    The returned callable is **stable per service class** so it can be
    overridden in tests via ``app.dependency_overrides[get_service(Foo)]``.
    """
    cached = _DEP_CACHE.get(service_cls)
    if cached is not None:
        return cached  # type: ignore[return-value]

    def _dep(request: Request) -> S:
        sf: async_sessionmaker[AsyncSession] | None = getattr(
            request.app.state, "session_factory", None
        )
        if sf is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database session factory not configured",
            )
        return service_cls(sf)  # type: ignore[call-arg]

    _dep.__name__ = f"get_{service_cls.__name__}"
    _DEP_CACHE[service_cls] = _dep
    return _dep


__all__ = [
    "ComplianceExportService",
    "IncidentSimilarityService",
    "InvestigationTimelineService",
    "InvestigationWriteService",
    "OnboardingProgressService",
    "get_service",
]
