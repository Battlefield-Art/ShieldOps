"""Node implementations for the Session Hijack Detector Agent LangGraph workflow."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.session_hijack_detector.models import (
    HijackIndicator,
    HijackReport,
    ReasoningStep,
    ResponseAction,
    SessionEvent,
    SessionHijackDetectorState,
)
from shieldops.agents.session_hijack_detector.prompts import (
    SYSTEM_ANALYZE,
    SYSTEM_ASSESS_RISK,
    SYSTEM_CORRELATE,
    AnomalyAnalysisOutput,
    CorrelationOutput,
    RiskAssessmentOutput,
)
from shieldops.agents.session_hijack_detector.tools import (
    SessionHijackDetectorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SessionHijackDetectorToolkit | None = None


def set_toolkit(toolkit: SessionHijackDetectorToolkit) -> None:
    """Set the shared toolkit instance."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> SessionHijackDetectorToolkit:
    if _toolkit is None:
        return SessionHijackDetectorToolkit()
    return _toolkit


async def collect_sessions(
    state: SessionHijackDetectorState,
) -> dict[str, Any]:
    """Collect and normalize session events from raw telemetry."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.collect_session_events(
        state.raw_events,
    )
    sessions = [SessionEvent(**e) for e in raw if isinstance(e, dict)]
    unique_users = len({s.user_id for s in sessions if s.user_id})

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="collect_sessions",
        input_summary=(f"Processing {len(state.raw_events)} raw events"),
        output_summary=(f"Collected {len(sessions)} sessions, {unique_users} unique users"),
        duration_ms=int(
            (datetime.now(UTC) - start).total_seconds() * 1000,
        ),
        tool_used="session_collector",
    )

    await toolkit.record_metric(
        "sessions_collected",
        float(len(sessions)),
    )

    return {
        "sessions": sessions,
        "unique_users": unique_users,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_sessions",
        "session_start": start,
    }


async def analyze_anomalies(
    state: SessionHijackDetectorState,
) -> dict[str, Any]:
    """Analyze sessions for hijack indicators."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    session_dicts = [s.model_dump() for s in state.sessions]

    # Run detection methods in sequence
    travel_indicators = await toolkit.detect_impossible_travel(
        session_dicts,
    )
    concurrent_indicators = await toolkit.detect_concurrent_sessions(session_dicts)
    token_indicators = await toolkit.detect_token_anomalies(
        session_dicts,
    )

    all_raw = travel_indicators + concurrent_indicators + token_indicators
    indicators = [HijackIndicator(**ind) for ind in all_raw if isinstance(ind, dict)]

    # LLM: enhance anomaly classification
    try:
        import json as _json

        context = _json.dumps(
            {
                "tenant_id": state.tenant_id,
                "session_count": len(state.sessions),
                "indicator_count": len(indicators),
                "indicators": [i.model_dump() for i in indicators[:20]],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ANALYZE,
            user_prompt=(f"Analyze session anomalies:\n{context}"),
            schema=AnomalyAnalysisOutput,
        )
        if hasattr(llm_result, "mitre_techniques"):
            for ind in indicators:
                if not ind.mitre_technique and llm_result.mitre_techniques:
                    ind.mitre_technique = llm_result.mitre_techniques[0]
        logger.info(
            "llm_enhanced",
            node="analyze_anomalies",
            types=getattr(llm_result, "hijack_types_detected", []),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_anomalies",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="analyze_anomalies",
        input_summary=(f"Analyzing {len(state.sessions)} sessions"),
        output_summary=(f"Found {len(indicators)} indicators"),
        duration_ms=int(
            (datetime.now(UTC) - start).total_seconds() * 1000,
        ),
        tool_used="anomaly_detector",
    )

    await toolkit.record_metric(
        "indicators_found",
        float(len(indicators)),
    )

    return {
        "indicators": indicators,
        "anomaly_count": len(indicators),
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_anomalies",
    }


async def correlate_indicators(
    state: SessionHijackDetectorState,
) -> dict[str, Any]:
    """Correlate indicators to confirm hijack attacks."""
    start = datetime.now(UTC)

    # Heuristic correlation: group by user and cross-reference
    by_user: dict[str, list[HijackIndicator]] = {}
    for ind in state.indicators:
        by_user.setdefault(ind.user_id, []).append(ind)

    confirmed: list[HijackIndicator] = []
    for _uid, user_inds in by_user.items():
        # Multiple indicator types = higher confidence
        types = {i.hijack_type for i in user_inds}
        if len(types) > 1 or any(i.confidence >= 0.8 for i in user_inds):
            for ind in user_inds:
                boosted = ind.model_copy()
                boosted.confidence = min(
                    ind.confidence + 0.1 * (len(types) - 1),
                    1.0,
                )
                confirmed.append(boosted)

    confirmed_count = len({c.user_id for c in confirmed})

    # LLM: deeper correlation
    try:
        import json as _json

        context = _json.dumps(
            {
                "tenant_id": state.tenant_id,
                "indicator_count": len(state.indicators),
                "indicators": [i.model_dump() for i in state.indicators[:20]],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CORRELATE,
            user_prompt=(f"Correlate hijack indicators:\n{context}"),
            schema=CorrelationOutput,
        )
        if hasattr(llm_result, "confirmed_hijack_count"):
            confirmed_count = max(
                confirmed_count,
                llm_result.confirmed_hijack_count,
            )
        logger.info(
            "llm_enhanced",
            node="correlate_indicators",
            confirmed=confirmed_count,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="correlate_indicators",
        )

    # If no correlated indicators, include high-confidence ones
    if not confirmed:
        confirmed = [i for i in state.indicators if i.confidence >= 0.7]

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="correlate_indicators",
        input_summary=(f"Correlating {len(state.indicators)} indicators"),
        output_summary=(
            f"Confirmed {confirmed_count} hijacks, {len(confirmed)} correlated indicators"
        ),
        duration_ms=int(
            (datetime.now(UTC) - start).total_seconds() * 1000,
        ),
        tool_used=None,
    )

    return {
        "correlated_indicators": confirmed,
        "confirmed_hijacks": confirmed_count,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "correlate_indicators",
    }


async def assess_risk(
    state: SessionHijackDetectorState,
) -> dict[str, Any]:
    """Assess overall risk from confirmed hijack indicators."""
    start = datetime.now(UTC)

    # Heuristic risk scoring
    risk_weights = {
        "critical": 30.0,
        "high": 20.0,
        "medium": 10.0,
        "low": 5.0,
        "info": 1.0,
    }
    base_risk = 0.0
    for ind in state.correlated_indicators:
        base_risk += risk_weights.get(ind.risk, 5.0)

    # Boost for multiple hijack types
    hijack_types = {i.hijack_type for i in state.correlated_indicators}
    base_risk += len(hijack_types) * 5.0

    risk_score = min(base_risk, 100.0)
    auto_respond = risk_score >= 85.0

    # Map score to level
    if risk_score >= 80:
        overall_risk = "critical"
    elif risk_score >= 60:
        overall_risk = "high"
    elif risk_score >= 40:
        overall_risk = "medium"
    elif risk_score >= 20:
        overall_risk = "low"
    else:
        overall_risk = "info"

    # LLM: refine risk assessment
    try:
        import json as _json

        context = _json.dumps(
            {
                "tenant_id": state.tenant_id,
                "confirmed_hijacks": state.confirmed_hijacks,
                "indicator_count": len(state.correlated_indicators),
                "hijack_types": list(hijack_types),
                "heuristic_risk": risk_score,
                "indicators": [i.model_dump() for i in state.correlated_indicators[:15]],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ASSESS_RISK,
            user_prompt=(f"Assess session hijack risk:\n{context}"),
            schema=RiskAssessmentOutput,
        )
        if hasattr(llm_result, "risk_score"):
            risk_score = round(
                (risk_score + llm_result.risk_score) / 2,
                2,
            )
        if hasattr(llm_result, "auto_respond"):
            auto_respond = llm_result.auto_respond
        logger.info(
            "llm_enhanced",
            node="assess_risk",
            risk=risk_score,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_risk",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="assess_risk",
        input_summary=(f"Confirmed={state.confirmed_hijacks}, types={len(hijack_types)}"),
        output_summary=(f"Risk={risk_score}, level={overall_risk}, auto_respond={auto_respond}"),
        duration_ms=int(
            (datetime.now(UTC) - start).total_seconds() * 1000,
        ),
        tool_used=None,
    )

    return {
        "overall_risk": overall_risk,
        "risk_score": risk_score,
        "auto_respond": auto_respond,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_risk",
    }


async def respond(
    state: SessionHijackDetectorState,
) -> dict[str, Any]:
    """Execute response actions for confirmed hijacks."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    actions: list[ResponseAction] = []
    affected_sessions: set[str] = set()
    affected_users: set[str] = set()

    for ind in state.correlated_indicators:
        if ind.session_id:
            affected_sessions.add(ind.session_id)
        if ind.user_id:
            affected_users.add(ind.user_id)

    # Invalidate hijacked sessions
    for sid in affected_sessions:
        actions.append(
            ResponseAction(
                action_id=f"ra-{uuid4().hex[:8]}",
                action_type="invalidate_session",
                target_session_id=sid,
                target_user_id="",
                reason=f"Hijack detected on session {sid}",
                requires_approval=not state.auto_respond,
            )
        )

    # Force re-authentication for affected users
    for uid in affected_users:
        actions.append(
            ResponseAction(
                action_id=f"ra-{uuid4().hex[:8]}",
                action_type="force_reauth",
                target_session_id="",
                target_user_id=uid,
                reason=f"Session hijack confirmed for {uid}",
                requires_approval=not state.auto_respond,
            )
        )

    # Block anomalous IPs
    blocked_ips: set[str] = set()
    for ind in state.correlated_indicators:
        if ind.anomalous_ip and ind.confidence >= 0.8:
            blocked_ips.add(ind.anomalous_ip)
    for ip in blocked_ips:
        actions.append(
            ResponseAction(
                action_id=f"ra-{uuid4().hex[:8]}",
                action_type="block_ip",
                target_session_id="",
                target_user_id="",
                reason=f"Anomalous IP {ip} linked to hijack",
                requires_approval=not state.auto_respond,
            )
        )

    # Execute actions not requiring approval
    executable = [a.model_dump() for a in actions if not a.requires_approval]
    results = await toolkit.execute_response(executable)

    result_map = {r.get("action_id", ""): r for r in results}
    for action in actions:
        if action.action_id in result_map:
            r = result_map[action.action_id]
            action.executed = r.get("executed", False)
            action.result = r.get("result", "")
            action.execution_time_ms = r.get(
                "execution_time_ms",
                0,
            )

    executed_count = sum(1 for a in actions if a.executed)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="respond",
        input_summary=(
            f"Responding to {len(affected_sessions)} sessions, {len(affected_users)} users"
        ),
        output_summary=(f"Executed {executed_count}/{len(actions)} actions"),
        duration_ms=int(
            (datetime.now(UTC) - start).total_seconds() * 1000,
        ),
        tool_used="response_engine",
    )

    await toolkit.record_metric(
        "responses_executed",
        float(executed_count),
    )

    return {
        "response_actions": actions,
        "responses_executed": executed_count,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "respond",
    }


async def report(
    state: SessionHijackDetectorState,
) -> dict[str, Any]:
    """Generate final session hijack detection report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int(
            (datetime.now(UTC) - state.session_start).total_seconds() * 1000,
        )

    hijack_types = list({i.hijack_type for i in state.correlated_indicators})
    affected_users = list({i.user_id for i in state.correlated_indicators if i.user_id})

    risk_summary: dict[str, int] = {}
    for ind in state.correlated_indicators:
        risk_summary[ind.risk] = risk_summary.get(ind.risk, 0) + 1

    executed_count = sum(1 for a in state.response_actions if a.executed)

    summary = (
        f"Session hijack detection for "
        f"{state.tenant_id}: "
        f"{state.confirmed_hijacks} hijacks confirmed. "
        f"{len(state.sessions)} sessions analyzed, "
        f"{state.anomaly_count} anomalies, "
        f"{executed_count} responses executed. "
        f"Risk: {state.overall_risk} ({state.risk_score:.1f})."
    )

    hijack_report = HijackReport(
        report_id=f"shr-{uuid4().hex[:12]}",
        tenant_id=state.tenant_id,
        sessions_analyzed=len(state.sessions),
        indicators_found=state.anomaly_count,
        hijacks_confirmed=state.confirmed_hijacks,
        responses_executed=executed_count,
        hijack_types=hijack_types,
        affected_users=affected_users,
        risk_summary=risk_summary,
        summary=summary,
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="report",
        input_summary=(f"Generating report for {state.detection_id}"),
        output_summary=(f"Confirmed={state.confirmed_hijacks}, risk={state.overall_risk}"),
        duration_ms=int(
            (datetime.now(UTC) - start).total_seconds() * 1000,
        ),
        tool_used=None,
    )

    await toolkit.record_metric(
        "detection_duration_ms",
        float(duration_ms),
    )

    return {
        "report": hijack_report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
