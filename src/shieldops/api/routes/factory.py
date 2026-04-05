"""Route factory — generates standard agent CRUD routers.

Replaces the copy-paste pattern used across 888+ route files with a single
factory function that produces health / run / runs / runs/{id} endpoints.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse

logger = structlog.get_logger()


class DefaultRunRequest(BaseModel):
    """Minimal request body accepted by the /run endpoint."""

    tenant_id: str = ""
    model_config = {"extra": "forbid"}


def create_agent_router(
    name: str,
    *,
    run_method: str = "execute",
    request_model: type[BaseModel] | None = None,
    extra_routes: Callable[[APIRouter, Callable[[], Any]], None] | None = None,
) -> tuple[APIRouter, Callable[[Any], None]]:
    """Create a standard agent APIRouter with health/run/runs endpoints.

    Parameters
    ----------
    name:
        Snake-case agent name (e.g. ``"chaos_engineering"``).
    run_method:
        Name of the async method to call on the runner (default ``"execute"``).
    request_model:
        Pydantic model for the ``/run`` request body.  Falls back to
        :class:`DefaultRunRequest`.
    extra_routes:
        Optional callback ``(router, get_runner) -> None`` that can register
        additional endpoints on the router.

    Returns
    -------
    tuple[APIRouter, set_runner]
        The configured router and a ``set_runner(runner)`` callable used at
        startup to inject the agent runner instance.
    """
    prefix = "/" + name.replace("_", "-")
    tag = name.replace("_", " ").title()
    router = APIRouter(prefix=prefix, tags=[tag])

    _holder: dict[str, Any] = {}

    def set_runner(runner: Any) -> None:
        _holder["runner"] = runner

    def _get_runner() -> Any:
        r = _holder.get("runner")
        if r is None:
            raise HTTPException(503, f"{tag} service not initialized")
        return r

    req_model = request_model or DefaultRunRequest

    @router.get("/health", operation_id=f"{name}_health")
    async def health() -> dict[str, Any]:
        return {
            "service": name.replace("_", "-"),
            "status": "healthy" if _holder.get("runner") else "not_initialized",
            "timestamp": time.time(),
        }

    @router.post("/run", operation_id=f"{name}_run")
    async def run_agent(
        request: Request,
        _user: UserResponse = Depends(get_current_user),
    ) -> dict[str, Any]:
        try:
            raw = await request.json()
        except Exception:
            raw = {}
        try:
            body = req_model.model_validate(raw)
        except Exception as exc:
            raise HTTPException(422, str(exc)) from exc
        runner = _get_runner()
        method = getattr(runner, run_method, None)
        if method is None:
            raise HTTPException(500, f"Runner has no method '{run_method}'")
        kwargs = body.model_dump(exclude_unset=True)
        try:
            result = await method(**kwargs)
        except Exception as exc:
            logger.exception(f"{name}.run.error")
            raise HTTPException(500, str(exc)) from exc
        if hasattr(result, "model_dump"):
            return {"status": "completed", "result": result.model_dump()}
        return {"status": "completed", "result": result}

    @router.get("/runs", operation_id=f"{name}_list_runs")
    async def list_runs(
        limit: int = 20,
        _user: UserResponse = Depends(get_current_user),
    ) -> dict[str, Any]:
        runner = _get_runner()
        results: Any = {}
        for attr in ("list_runs", "list_results", "_results"):
            val = getattr(runner, attr, None)
            if callable(val):
                try:
                    results = val(limit=limit)
                except TypeError:
                    results = val()
                break
            elif isinstance(val, dict):
                results = dict(list(val.items())[-limit:])
                break
        total = len(results) if isinstance(results, (list, dict)) else 0
        return {"runs": results, "total": total}

    @router.get("/runs/{run_id}", operation_id=f"{name}_get_run")
    async def get_run(
        run_id: str,
        _user: UserResponse = Depends(get_current_user),
    ) -> dict[str, Any]:
        runner = _get_runner()
        for attr in ("get_result", "get_run"):
            method = getattr(runner, attr, None)
            if method:
                result = method(run_id)
                if result is not None:
                    if hasattr(result, "model_dump"):
                        return result.model_dump()  # type: ignore[no-any-return]
                    return result if isinstance(result, dict) else {"result": result}
        raise HTTPException(404, f"Run {run_id} not found")

    if extra_routes is not None:
        extra_routes(router, _get_runner)

    return router, set_runner
