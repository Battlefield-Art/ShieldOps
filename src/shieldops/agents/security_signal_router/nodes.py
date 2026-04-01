"""Node implementations for the Security Signal Router Agent."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_signal_router.models import (
    ReasoningStep,
    SecuritySignalRouterState,
    SSRStage,
)
from shieldops.agents.security_signal_router.prompts import (
    SYSTEM_CLASSIFY,
    SYSTEM_DISPATCH,
    SYSTEM_EVALUATE_ROUTING,
    SYSTEM_INGEST,
    SYSTEM_TRACK_OUTCOMES,
    ClassificationOutput,
    DispatchOutput,
    OutcomeTrackingOutput,
    RoutingEvalOutput,
    SignalIngestionOutput,
)
from shieldops.agents.security_signal_router.tools import (
    SecuritySignalRouterToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecuritySignalRouterToolkit | None = None


def set_toolkit(
    toolkit: SecuritySignalRouterToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SecuritySignalRouterToolkit:
    if _toolkit is None:
        return SecuritySignalRouterToolkit()
    return _toolkit


def _step(
    state: SecuritySignalRouterState,
    action: str,
    input_summary: str,
    output_summary: str,
    duration_ms: int,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Create a reasoning step."""
    return ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=duration_ms,
        tool_used=tool_used,
    )


async def ingest_signals(
    state: SecuritySignalRouterState,
) -> dict[str, Any]:
    """Ingest security signals from configured sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.ingest_signals(state.config)

    try:
        ctx = _json.dumps(
            {
                "sources": state.config.get("sources", []),
                "signal_count": len(raw),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_INGEST,
            user_prompt=f"Signal ingestion context:\n{ctx}",
            schema=SignalIngestionOutput,
        )
        if hasattr(llm_result, "total_ingested"):
            logger.info("llm_enhanced", node="ingest_signals")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="ingest_signals")

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "ingest_signals",
        f"sources={state.config.get('sources', [])}",
        f"ingested {len(raw)} signals",
        elapsed,
        "signal_bus",
    )
    await toolkit.record_metric("signals_ingested", float(len(raw)))

    return {
        "signals": raw,
        "stage": SSRStage.CLASSIFY_SIGNALS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "ingest_signals",
        "session_start": start,
    }


async def classify_signals(
    state: SecuritySignalRouterState,
) -> dict[str, Any]:
    """Classify signals by category and priority."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    classified = await toolkit.classify_signals(state.signals)
    threat_count = sum(1 for c in classified if c.get("category") == "threat")

    try:
        ctx = _json.dumps(
            {
                "signal_count": len(state.signals),
                "classified_count": len(classified),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CLASSIFY,
            user_prompt=f"Classification context:\n{ctx}",
            schema=ClassificationOutput,
        )
        if hasattr(llm_result, "classified_count"):
            logger.info("llm_enhanced", node="classify_signals")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="classify_signals",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "classify_signals",
        f"classifying {len(state.signals)} signals",
        f"{len(classified)} classified, {threat_count} threats",
        elapsed,
        "classifier",
    )

    return {
        "classified_signals": classified,
        "stage": SSRStage.EVALUATE_ROUTING,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "classify_signals",
    }


async def evaluate_routing(
    state: SecuritySignalRouterState,
) -> dict[str, Any]:
    """Evaluate routing decisions for classified signals."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    decisions = await toolkit.evaluate_routing(
        state.classified_signals,
        state.config,
    )

    try:
        ctx = _json.dumps(
            {
                "classified_count": len(state.classified_signals),
                "decision_count": len(decisions),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_EVALUATE_ROUTING,
            user_prompt=f"Routing evaluation context:\n{ctx}",
            schema=RoutingEvalOutput,
        )
        if hasattr(llm_result, "routes_evaluated"):
            logger.info("llm_enhanced", node="evaluate_routing")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="evaluate_routing",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "evaluate_routing",
        f"evaluating {len(state.classified_signals)} signals",
        f"{len(decisions)} routing decisions",
        elapsed,
        "router",
    )
    await toolkit.record_metric(
        "routing_decisions",
        float(len(decisions)),
    )

    return {
        "routing_decisions": decisions,
        "stage": SSRStage.DISPATCH_SIGNALS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "evaluate_routing",
    }


async def dispatch_signals(
    state: SecuritySignalRouterState,
) -> dict[str, Any]:
    """Dispatch signals to target agents."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.dispatch_signals(
        state.routing_decisions,
    )
    dispatched = sum(1 for r in results if r.get("dispatched"))

    try:
        ctx = _json.dumps(
            {
                "decision_count": len(state.routing_decisions),
                "dispatched": dispatched,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_DISPATCH,
            user_prompt=f"Dispatch context:\n{ctx}",
            schema=DispatchOutput,
        )
        if hasattr(llm_result, "dispatched_count"):
            logger.info("llm_enhanced", node="dispatch_signals")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="dispatch_signals",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "dispatch_signals",
        f"dispatching {len(state.routing_decisions)} decisions",
        f"{dispatched}/{len(results)} dispatched",
        elapsed,
        "dispatcher",
    )

    return {
        "dispatch_results": results,
        "stage": SSRStage.TRACK_OUTCOMES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "dispatch_signals",
    }


async def track_outcomes(
    state: SecuritySignalRouterState,
) -> dict[str, Any]:
    """Track resolution outcomes for dispatched signals."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    outcomes = await toolkit.track_outcomes(state.dispatch_results)
    resolved = sum(1 for o in outcomes if o.get("resolved"))

    try:
        ctx = _json.dumps(
            {
                "dispatch_count": len(state.dispatch_results),
                "resolved": resolved,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_TRACK_OUTCOMES,
            user_prompt=f"Outcome tracking context:\n{ctx}",
            schema=OutcomeTrackingOutput,
        )
        if hasattr(llm_result, "resolved_count"):
            logger.info("llm_enhanced", node="track_outcomes")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="track_outcomes",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "track_outcomes",
        f"tracking {len(state.dispatch_results)} dispatches",
        f"{resolved}/{len(outcomes)} resolved",
        elapsed,
        "outcome_tracker",
    )
    await toolkit.record_metric("signals_resolved", float(resolved))

    return {
        "outcome_records": outcomes,
        "stage": SSRStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "track_outcomes",
    }


async def generate_report(
    state: SecuritySignalRouterState,
) -> dict[str, Any]:
    """Generate final signal routing report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int(
            (datetime.now(UTC) - state.session_start).total_seconds() * 1000,
        )

    report = {
        "request_id": state.request_id,
        "signals_ingested": len(state.signals),
        "signals_classified": len(state.classified_signals),
        "routing_decisions": len(state.routing_decisions),
        "dispatched": len(state.dispatch_results),
        "outcomes_tracked": len(state.outcome_records),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric(
        "scan_duration_ms",
        float(duration_ms),
    )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "generate_report",
        f"finalizing {state.request_id}",
        f"report complete in {duration_ms}ms",
        elapsed,
        None,
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
