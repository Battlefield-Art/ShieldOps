"""Framework integration — #246 PR-2: auto-apply evolution tracking.

See ghantakiran/ShieldOps#246. This module provides the single
decorator ``tracked_run`` that :func:`shieldops.agents.framework.define_agent`
applies to the generated ``AgentRunner.run`` method so every run
automatically feeds a :class:`RunOutcome` into the
:class:`EvolutionStore` via the handle returned by
:meth:`EvolutionStore.for_agent`.

The decorator is tolerant of a missing store — when
:func:`get_evolution_store` raises because nothing is installed, it
logs a warning once and passes the call through unwrapped. This is the
compatibility guarantee that kept the existing 114-agent test suite
green during rollout: framework-built agents are constructed at
import time (before ``app.py`` lifespan installs the store), so the
wrap must be safe when the store is None.

Exception safety: the ``RunOutcome`` mapping + the ``evolution.record``
call are wrapped in ``try/except`` inside the wrapper so any bug in the
evolution subsystem cannot crash the agent call. This matches the
"exception safety" invariant locked by the RFC #246 PR-1 contract test
``test_record_run_exception_does_not_crash_caller``.
"""

from __future__ import annotations

import functools
import inspect
import time
from collections.abc import Callable
from typing import Any, TypeVar

import structlog

from shieldops.utils.evolution.composition import get_evolution_store
from shieldops.utils.evolution.store import RunOutcome

logger = structlog.get_logger(__name__)

F = TypeVar("F", bound=Callable[..., Any])

# Marker for idempotency — same pattern as RFC #244's _shieldops_enforced.
_TRACKED_MARKER = "_shieldops_evolution_tracked"

_missing_store_warned: bool = False


def _try_get_store() -> Any | None:
    """Return the installed evolution store or ``None`` if unset.

    Logs once when first missing, then silently returns ``None`` so
    the wrapper short-circuits.
    """
    global _missing_store_warned
    try:
        return get_evolution_store()
    except RuntimeError:
        if not _missing_store_warned:
            _missing_store_warned = True
            logger.warning(
                "evolution.tracked_run.store_not_installed",
                message=(
                    "tracked_run decorator invoked but no EvolutionStore "
                    "is installed. Tracking is a no-op until "
                    "set_evolution_store() is called at app startup."
                ),
            )
        return None


def _outcome_from_exception(latency_ms: float, exc: BaseException) -> RunOutcome:
    """Build a failed :class:`RunOutcome` from an exception."""
    return RunOutcome(
        success=False,
        latency_ms=latency_ms,
        error=f"{type(exc).__name__}: {exc}",
    )


def _outcome_from_success(latency_ms: float) -> RunOutcome:
    """Build a successful :class:`RunOutcome`. Token usage + cost are
    absent here; PR-3 will extract them from the LLM orchestrator
    (RFC #248) once the shim is in place.
    """
    return RunOutcome(success=True, latency_ms=latency_ms)


def tracked_run(agent_name: str) -> Callable[[F], F]:
    """Wrap a framework runner's ``run`` method with evolution tracking.

    The wrapped function:
    1. Records the start time via :func:`time.monotonic`.
    2. Calls the wrapped function.
    3. Builds a :class:`RunOutcome` from either the returned value
       (success path, inferring from ``state.error``) or the raised
       exception (failure path).
    4. Calls ``evolution.for_agent(agent_name).record(outcome)`` —
       wrapped in ``try/except`` so a broken evolution adapter cannot
       crash the agent call.
    5. Returns (or re-raises) the original result.

    Idempotent: re-applying this decorator to an already-tracked
    function is a no-op via the ``_shieldops_evolution_tracked`` marker.
    """

    def decorator(func: F) -> F:
        if getattr(func, _TRACKED_MARKER, False):
            return func

        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                store = _try_get_store()
                if store is None:
                    return await func(*args, **kwargs)
                start = time.monotonic()
                try:
                    result = await func(*args, **kwargs)
                except BaseException as exc:  # noqa: BLE001
                    latency_ms = (time.monotonic() - start) * 1000.0
                    _record_safely(store, agent_name, _outcome_from_exception(latency_ms, exc))
                    raise
                latency_ms = (time.monotonic() - start) * 1000.0
                success = not _result_has_error(result)
                outcome = (
                    _outcome_from_success(latency_ms)
                    if success
                    else RunOutcome(
                        success=False,
                        latency_ms=latency_ms,
                        error=_extract_error(result),
                    )
                )
                _record_safely(store, agent_name, outcome)
                return result

            async_wrapper._shieldops_evolution_tracked = True  # type: ignore[attr-defined]
            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            store = _try_get_store()
            if store is None:
                return func(*args, **kwargs)
            start = time.monotonic()
            try:
                result = func(*args, **kwargs)
            except BaseException as exc:  # noqa: BLE001
                latency_ms = (time.monotonic() - start) * 1000.0
                _record_safely(store, agent_name, _outcome_from_exception(latency_ms, exc))
                raise
            latency_ms = (time.monotonic() - start) * 1000.0
            success = not _result_has_error(result)
            outcome = (
                _outcome_from_success(latency_ms)
                if success
                else RunOutcome(
                    success=False,
                    latency_ms=latency_ms,
                    error=_extract_error(result),
                )
            )
            _record_safely(store, agent_name, outcome)
            return result

        sync_wrapper._shieldops_evolution_tracked = True  # type: ignore[attr-defined]
        return sync_wrapper  # type: ignore[return-value]

    return decorator


def _result_has_error(result: Any) -> bool:
    """Infer success from the framework's state convention: the state
    has an ``error`` field that's empty on success and populated on
    failure. This matches ``framework.py``'s error-path behavior
    (state is returned with ``error=str(e)`` on exception)."""
    if result is None:
        return False
    err = getattr(result, "error", None)
    if err is None and isinstance(result, dict):
        err = result.get("error")
    return bool(err)


def _extract_error(result: Any) -> str:
    if result is None:
        return ""
    err = getattr(result, "error", None)
    if err is None and isinstance(result, dict):
        err = result.get("error")
    return str(err or "")


def _record_safely(store: Any, agent_name: str, outcome: RunOutcome) -> None:
    """Record the outcome + swallow any exception.

    The ``EvolutionStore.record_run`` body is already exception-safe
    (RFC #246 PR-1 locked that invariant), but we wrap the lookup +
    call pair defensively here too so a broken ``for_agent`` override
    cannot crash the caller.
    """
    try:
        store.for_agent(agent_name).record(outcome)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "evolution.tracked_run.record_failed",
            agent_name=agent_name,
            error=str(exc),
        )
