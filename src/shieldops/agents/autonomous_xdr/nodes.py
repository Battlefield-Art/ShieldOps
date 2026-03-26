"""Node implementations for the Autonomous XDR Agent.

Each node maps to a stage in the XDR pipeline:
collect -> normalize -> correlate -> detect -> investigate
-> respond -> report.
"""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.autonomous_xdr.models import (
    AutonomousXDRState,
    ReasoningStep,
)
from shieldops.agents.autonomous_xdr.prompts import (
    SYSTEM_CORRELATE,
    SYSTEM_INVESTIGATE,
    SYSTEM_REPORT,
    CorrelationOutput,
    InvestigationOutput,
    ReportOutput,
)
from shieldops.agents.autonomous_xdr.tools import (
    AutonomousXDRToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AutonomousXDRToolkit | None = None


def set_toolkit(toolkit: AutonomousXDRToolkit) -> None:
    """Inject toolkit for the module-level nodes."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> AutonomousXDRToolkit:
    if _toolkit is None:
        return AutonomousXDRToolkit()
    return _toolkit


# ── Node: collect_telemetry ────────────────────────────


async def collect_telemetry(
    state: AutonomousXDRState,
) -> dict[str, Any]:
    """Ingest telemetry from all vendor sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    domains = state.config.get("domains")
    vendors = state.config.get("vendors")
    time_range = state.config.get("time_range_hours", 24)

    signals = await toolkit.collect_telemetry(
        domains=domains,
        vendors=vendors,
        time_range_hours=time_range,
    )

    await toolkit.record_metric("signals_collected", float(len(signals)))

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="collect_telemetry",
        input_summary=(f"Collecting from {time_range}h window"),
        output_summary=(f"Collected {len(signals)} signals"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="collect_telemetry",
    )

    vendors_seen = list({s.vendor for s in signals})
    domains_seen = list({s.domain.value for s in signals})

    return {
        "signals_collected": signals,
        "vendors_queried": vendors_seen,
        "domains_covered": domains_seen,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "collect_telemetry",
        "session_start": start,
    }


# ── Node: normalize_signals ───────────────────────────


async def normalize_signals(
    state: AutonomousXDRState,
) -> dict[str, Any]:
    """Normalize raw signals to OCSF schema."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    alerts = await toolkit.normalize_to_ocsf(state.signals_collected)

    await toolkit.record_metric("alerts_normalized", float(len(alerts)))

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="normalize_signals",
        input_summary=(f"Normalizing {len(state.signals_collected)} signals"),
        output_summary=(f"Produced {len(alerts)} OCSF alerts"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="normalize_to_ocsf",
    )

    return {
        "normalized_alerts": alerts,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "normalize_signals",
    }


# ── Node: correlate_cross_domain ──────────────────────


async def correlate_cross_domain(
    state: AutonomousXDRState,
) -> dict[str, Any]:
    """Correlate alerts across domains with LLM."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    correlations = await toolkit.correlate_cross_domain(state.normalized_alerts)

    # LLM enhancement: deeper correlation analysis
    try:
        ctx = _json.dumps(
            {
                "alert_count": len(state.normalized_alerts),
                "correlation_count": len(correlations),
                "domains": state.domains_covered,
                "vendors": state.vendors_queried,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CORRELATE,
            user_prompt=(f"Cross-domain context:\n{ctx}"),
            schema=CorrelationOutput,
        )
        logger.info(
            "llm_enhanced",
            node="correlate_cross_domain",
            confidence=getattr(llm_result, "confidence", 0),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="correlate_cross_domain",
        )

    coverage = 0.0
    if state.normalized_alerts:
        corr_alert_ids: set[str] = set()
        for c in correlations:
            corr_alert_ids.update(c.alert_ids)
        coverage = round(
            len(corr_alert_ids) / len(state.normalized_alerts) * 100,
            1,
        )

    await toolkit.record_metric("correlations_found", float(len(correlations)))

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="correlate_cross_domain",
        input_summary=(f"Correlating {len(state.normalized_alerts)} alerts"),
        output_summary=(f"Found {len(correlations)} correlations, {coverage}% coverage"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="correlate_cross_domain",
    )

    return {
        "correlations_found": correlations,
        "detection_coverage_pct": coverage,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "correlate_cross_domain",
    }


# ── Node: detect_campaigns ────────────────────────────


async def detect_campaigns(
    state: AutonomousXDRState,
) -> dict[str, Any]:
    """Detect multi-stage attack campaigns."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    campaigns = await toolkit.detect_campaigns(
        state.correlations_found,
        state.normalized_alerts,
    )

    await toolkit.record_metric("campaigns_detected", float(len(campaigns)))

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="detect_campaigns",
        input_summary=(f"Analyzing {len(state.correlations_found)} correlations"),
        output_summary=(f"Detected {len(campaigns)} campaigns"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="detect_campaigns",
    )

    return {
        "campaigns_detected": campaigns,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "detect_campaigns",
    }


# ── Node: auto_investigate ─────────────────────────────


async def auto_investigate(
    state: AutonomousXDRState,
) -> dict[str, Any]:
    """Run automated investigation on campaigns."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    investigations = []
    for campaign in state.campaigns_detected:
        inv = await toolkit.auto_investigate(campaign, state.correlations_found)
        investigations.append(inv)

    # LLM enhancement: deeper investigation
    try:
        inv_ctx = _json.dumps(
            {
                "campaigns": len(state.campaigns_detected),
                "investigations": len(investigations),
                "total_assets": sum(len(i.compromised_assets) for i in investigations),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_INVESTIGATE,
            user_prompt=(f"Investigation context:\n{inv_ctx}"),
            schema=InvestigationOutput,
        )
        logger.info(
            "llm_enhanced",
            node="auto_investigate",
            urgency=getattr(llm_result, "containment_urgency", ""),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="auto_investigate",
        )

    await toolkit.record_metric(
        "investigations_completed",
        float(len(investigations)),
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="auto_investigate",
        input_summary=(f"Investigating {len(state.campaigns_detected)} campaigns"),
        output_summary=(f"Completed {len(investigations)} investigations"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="auto_investigate",
    )

    return {
        "investigations_completed": investigations,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "auto_investigate",
    }


# ── Node: respond ─────────────────────────────────────


async def respond(
    state: AutonomousXDRState,
) -> dict[str, Any]:
    """Execute automated response actions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    all_responses: list[dict[str, Any]] = []
    for inv in state.investigations_completed:
        responses = await toolkit.execute_response(inv)
        all_responses.extend(responses)

    await toolkit.record_metric(
        "responses_executed",
        float(len(all_responses)),
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="respond",
        input_summary=(f"Responding to {len(state.investigations_completed)} investigations"),
        output_summary=(f"Executed {len(all_responses)} responses"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="execute_response",
    )

    return {
        "auto_responses": all_responses,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "respond",
    }


# ── Node: report ──────────────────────────────────────


async def report(
    state: AutonomousXDRState,
) -> dict[str, Any]:
    """Generate executive XDR report and finalize."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    # LLM enhancement: executive report
    try:
        rpt_ctx = _json.dumps(
            {
                "signals": len(state.signals_collected),
                "alerts": len(state.normalized_alerts),
                "correlations": len(state.correlations_found),
                "campaigns": len(state.campaigns_detected),
                "investigations": len(state.investigations_completed),
                "responses": len(state.auto_responses),
                "coverage_pct": (state.detection_coverage_pct),
                "domains": state.domains_covered,
                "vendors": state.vendors_queried,
                "duration_ms": duration_ms,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"XDR report context:\n{rpt_ctx}",
            schema=ReportOutput,
        )
        logger.info(
            "llm_enhanced",
            node="report",
            risk_level=getattr(llm_result, "risk_level", ""),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="report",
        )

    await toolkit.record_metric("xdr_duration_ms", float(duration_ms))

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="report",
        input_summary="Generating executive report",
        output_summary=(f"Session complete in {duration_ms}ms"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used=None,
    )

    return {
        "session_duration_ms": duration_ms,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "complete",
    }
