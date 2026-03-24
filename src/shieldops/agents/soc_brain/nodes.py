"""Node implementations for the SOC Brain Agent LangGraph workflow."""

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.soc_brain.models import (
    ActionType,
    CorrelatedFinding,
    ExecutedAction,
    NormalizedEvent,
    ReasoningStep,
    RecommendedAction,
    Situation,
    SOCBrainState,
)
from shieldops.agents.soc_brain.prompts import (
    SYSTEM_ACTION_RECOMMENDATION,
    SYSTEM_CROSS_VENDOR_CORRELATION,
    SYSTEM_EVENT_TRIAGE,
    SYSTEM_SITUATION_ANALYSIS,
    ActionRecommendationOutput,
    CorrelationOutput,
    SituationAnalysisOutput,
    TriageOutput,
)
from shieldops.agents.soc_brain.tools import SOCBrainToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SOCBrainToolkit | None = None


def set_toolkit(toolkit: SOCBrainToolkit) -> None:
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> SOCBrainToolkit:
    if _toolkit is None:
        return SOCBrainToolkit()
    return _toolkit


async def ingest_telemetry(state: SOCBrainState) -> dict[str, Any]:
    """Pull detections from all configured vendor sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    vendor_detections: dict[str, list[dict[str, Any]]] = {}
    vendors = state.vendor_sources or ["crowdstrike", "defender", "wiz"]

    for vendor in vendors:
        try:
            if vendor == "crowdstrike":
                detections = await toolkit.ingest_from_crowdstrike(
                    filter_query=state.trigger_data.get("filter_query", ""),
                    time_range_minutes=state.trigger_data.get("time_range_minutes", 60),
                )
            elif vendor == "defender":
                detections = await toolkit.ingest_from_defender(
                    time_range_minutes=state.trigger_data.get("time_range_minutes", 60),
                )
            elif vendor == "wiz":
                detections = await toolkit.ingest_from_wiz(
                    severity=state.trigger_data.get("wiz_severity", "HIGH"),
                )
            else:
                detections = []
            vendor_detections[vendor] = detections
        except Exception as exc:
            logger.warning(
                "soc_brain.ingest_failed",
                vendor=vendor,
                error=str(exc),
            )
            vendor_detections[vendor] = []

    total = sum(len(v) for v in vendor_detections.values())
    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="ingest_telemetry",
        input_summary=f"Ingesting from {len(vendors)} vendors",
        output_summary=f"Ingested {total} detections across {len(vendors)} vendors",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="vendor_connectors",
    )

    return {
        "vendor_detections": vendor_detections,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "ingest_telemetry",
        "session_start": start,
    }


async def normalize_events(state: SOCBrainState) -> dict[str, Any]:
    """Normalize raw vendor events to a unified schema."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    normalized: list[NormalizedEvent] = []
    for vendor, detections in state.vendor_detections.items():
        for raw_event in detections:
            norm_data = await toolkit.normalize_event(vendor, raw_event)
            normalized.append(NormalizedEvent(**norm_data))

    # Also include any events from trigger_data (single-alert mode)
    if state.trigger_type.value == "alert" and state.trigger_data.get("event"):
        vendor = state.trigger_data.get("vendor", "unknown")
        norm_data = await toolkit.normalize_event(vendor, state.trigger_data["event"])
        normalized.append(NormalizedEvent(**norm_data))

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="normalize_events",
        input_summary=f"Normalizing events from {len(state.vendor_detections)} vendors",
        output_summary=f"Normalized {len(normalized)} events",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="event_normalizer",
    )

    return {
        "normalized_events": normalized,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "normalize_events",
    }


async def correlate_findings(state: SOCBrainState) -> dict[str, Any]:
    """Cross-vendor correlation of normalized events."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    events_as_dicts = [e.model_dump() for e in state.normalized_events]
    raw_correlations = await toolkit.correlate_events(events_as_dicts)

    # LLM-enhanced correlation
    try:
        context = _json.dumps(
            {
                "event_count": len(events_as_dicts),
                "vendors": list({e.get("vendor", "") for e in events_as_dicts}),
                "events_summary": [
                    {
                        "id": e.get("event_id"),
                        "vendor": e.get("vendor"),
                        "type": e.get("event_type"),
                        "severity": e.get("severity"),
                        "hostname": e.get("hostname"),
                        "source_ip": e.get("source_ip"),
                        "user": e.get("user"),
                        "mitre": e.get("mitre_technique"),
                    }
                    for e in events_as_dicts[:30]
                ],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CROSS_VENDOR_CORRELATION,
            user_prompt=f"Events to correlate:\n{context}",
            schema=CorrelationOutput,
        )
        if hasattr(llm_result, "cross_vendor_insights"):
            logger.info(
                "llm_enhanced",
                node="correlate_findings",
                confidence=getattr(llm_result, "correlation_confidence", 0),
            )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="correlate_findings")

    correlated = [CorrelatedFinding(**c) for c in raw_correlations if isinstance(c, dict)]

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="correlate_findings",
        input_summary=f"Correlating {len(state.normalized_events)} normalized events",
        output_summary=f"Found {len(correlated)} correlated findings",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="cross_vendor_correlator",
    )

    # Track MTTD — time from first event to correlation
    mttd_ms = 0
    if state.session_start:
        mttd_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    return {
        "correlated_findings": correlated,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "correlate_findings",
        "mttd_ms": mttd_ms,
    }


async def triage_events(state: SOCBrainState) -> dict[str, Any]:
    """LLM-powered triage — determine if events constitute a situation."""
    start = datetime.now(UTC)

    has_situation = len(state.correlated_findings) > 0

    # LLM-powered triage for richer analysis
    try:
        triage_context = _json.dumps(
            {
                "trigger_type": state.trigger_type.value,
                "normalized_event_count": len(state.normalized_events),
                "correlated_finding_count": len(state.correlated_findings),
                "vendors": list({e.vendor for e in state.normalized_events}),
                "severities": list({e.severity for e in state.normalized_events}),
                "findings_summary": [
                    {
                        "id": f.finding_id,
                        "vendors": f.vendors,
                        "severity": f.severity,
                        "description": f.description,
                        "affected_assets": f.affected_assets[:5],
                    }
                    for f in state.correlated_findings[:10]
                ],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_EVENT_TRIAGE,
            user_prompt=f"Triage context:\n{triage_context}",
            schema=TriageOutput,
        )
        if hasattr(llm_result, "is_situation"):
            has_situation = llm_result.is_situation
        logger.info(
            "llm_enhanced",
            node="triage_events",
            is_situation=has_situation,
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="triage_events")

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="triage_events",
        input_summary=f"Triaging {len(state.correlated_findings)} correlated findings",
        output_summary=f"Situation detected: {has_situation}",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )

    # Store triage result in enrichment_data for routing
    enrichment = {**state.enrichment_data, "has_situation": has_situation}

    return {
        "enrichment_data": enrichment,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "triage_events",
    }


async def create_situations(state: SOCBrainState) -> dict[str, Any]:
    """Group correlated findings into actionable situations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    situations: list[Situation] = []
    for finding in state.correlated_findings:
        sit_data = await toolkit.create_situation(
            findings=[finding.model_dump()],
            severity=finding.severity,
            title=finding.description[:100] if finding.description else "Security Situation",
            description=finding.description,
        )
        situations.append(Situation(**sit_data))

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="create_situations",
        input_summary=f"Creating situations from {len(state.correlated_findings)} findings",
        output_summary=f"Created {len(situations)} situations",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="situation_engine",
    )

    return {
        "situations_created": situations,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "create_situations",
    }


async def analyze_situations(state: SOCBrainState) -> dict[str, Any]:
    """Deep LLM-powered analysis of each situation (MITRE, kill chain, blast radius)."""
    start = datetime.now(UTC)

    updated_situations: list[Situation] = []
    kill_chain_mapping: dict[str, list[str]] = {}

    for situation in state.situations_created:
        try:
            analysis_context = _json.dumps(
                {
                    "situation_id": situation.situation_id,
                    "title": situation.title,
                    "description": situation.description,
                    "severity": situation.severity,
                    "vendor_sources": situation.vendor_sources,
                    "affected_assets": situation.affected_assets[:10],
                    "correlated_event_count": situation.correlated_event_count,
                    "existing_mitre": situation.mitre_techniques,
                },
                default=str,
            )
            llm_result = await llm_structured(
                system_prompt=SYSTEM_SITUATION_ANALYSIS,
                user_prompt=f"Analyze this situation:\n{analysis_context}",
                schema=SituationAnalysisOutput,
            )
            situation.mitre_techniques = list(
                set(situation.mitre_techniques + getattr(llm_result, "mitre_techniques", []))
            )
            situation.kill_chain_phase = getattr(llm_result, "kill_chain_phase", "")
            situation.blast_radius = getattr(llm_result, "blast_radius", "")
            situation.ai_summary = getattr(llm_result, "ai_summary", "")

            if situation.kill_chain_phase:
                kill_chain_mapping.setdefault(situation.kill_chain_phase, []).append(
                    situation.situation_id
                )

            logger.info(
                "llm_enhanced",
                node="analyze_situations",
                situation_id=situation.situation_id,
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="analyze_situations",
                situation_id=situation.situation_id,
            )

        updated_situations.append(situation)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="analyze_situations",
        input_summary=f"Analyzing {len(state.situations_created)} situations",
        output_summary=f"Analyzed {len(updated_situations)} situations, "
        f"mapped {len(kill_chain_mapping)} kill chain phases",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )

    # Track MTTA — time from session start to analysis complete
    mtta_ms = 0
    if state.session_start:
        mtta_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    return {
        "situations_created": updated_situations,
        "kill_chain_mapping": kill_chain_mapping,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_situations",
        "mtta_ms": mtta_ms,
    }


async def recommend_actions(state: SOCBrainState) -> dict[str, Any]:
    """Generate action recommendations with confidence scores."""
    start = datetime.now(UTC)

    recommended: list[RecommendedAction] = []
    escalations: list[dict[str, Any]] = []

    for situation in state.situations_created:
        try:
            rec_context = _json.dumps(
                {
                    "situation_id": situation.situation_id,
                    "title": situation.title,
                    "severity": situation.severity,
                    "status": situation.status,
                    "vendor_sources": situation.vendor_sources,
                    "mitre_techniques": situation.mitre_techniques,
                    "kill_chain_phase": situation.kill_chain_phase,
                    "blast_radius": situation.blast_radius,
                    "affected_assets": situation.affected_assets[:10],
                    "ai_summary": situation.ai_summary,
                },
                default=str,
            )
            llm_result = await llm_structured(
                system_prompt=SYSTEM_ACTION_RECOMMENDATION,
                user_prompt=f"Recommend actions for this situation:\n{rec_context}",
                schema=ActionRecommendationOutput,
            )

            auto_indices = set(getattr(llm_result, "auto_approve_eligible", []))
            for idx, action_dict in enumerate(getattr(llm_result, "actions", [])):
                from uuid import uuid4

                rec = RecommendedAction(
                    action_id=f"act-{uuid4().hex[:12]}",
                    situation_id=situation.situation_id,
                    action_type=ActionType(action_dict.get("type", "investigate")),
                    vendor=action_dict.get("vendor", ""),
                    target=action_dict.get("target", ""),
                    description=action_dict.get("description", ""),
                    confidence=0.85 if idx in auto_indices else 0.6,
                    auto_approved=idx in auto_indices,
                    risk_level=action_dict.get("risk_level", "medium"),
                    estimated_impact=action_dict.get("impact", ""),
                )
                recommended.append(rec)

            if getattr(llm_result, "escalation_needed", False):
                escalations.append(
                    {
                        "situation_id": situation.situation_id,
                        "reason": getattr(llm_result, "escalation_reason", ""),
                        "severity": situation.severity,
                    }
                )

            logger.info(
                "llm_enhanced",
                node="recommend_actions",
                situation_id=situation.situation_id,
                action_count=len(getattr(llm_result, "actions", [])),
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="recommend_actions",
                situation_id=situation.situation_id,
            )
            # Fallback: basic containment recommendation
            from uuid import uuid4

            recommended.append(
                RecommendedAction(
                    action_id=f"act-{uuid4().hex[:12]}",
                    situation_id=situation.situation_id,
                    action_type=ActionType.INVESTIGATE,
                    vendor=situation.vendor_sources[0] if situation.vendor_sources else "",
                    target=situation.affected_assets[0] if situation.affected_assets else "",
                    description=f"Investigate situation: {situation.title}",
                    confidence=0.5,
                    auto_approved=False,
                    risk_level="low",
                )
            )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="recommend_actions",
        input_summary=f"Generating recommendations for {len(state.situations_created)} situations",
        output_summary=f"Recommended {len(recommended)} actions, {len(escalations)} escalations",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )

    return {
        "recommended_actions": recommended,
        "escalations": escalations,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "recommend_actions",
    }


async def execute_response(state: SOCBrainState) -> dict[str, Any]:
    """Execute auto-approved actions via vendor connectors."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    executed: list[ExecutedAction] = []
    auto_actions = [a for a in state.recommended_actions if a.auto_approved]

    for action in auto_actions:
        exec_start = datetime.now(UTC).isoformat()
        try:
            if action.action_type in (ActionType.CONTAIN,):
                result = await toolkit.execute_containment(
                    vendor=action.vendor,
                    target=action.target,
                    action=action.description,
                )
            elif action.action_type in (ActionType.REMEDIATE,):
                result = await toolkit.execute_remediation(
                    vendor=action.vendor,
                    target=action.target,
                    action=action.description,
                )
            else:
                result = {"status": "skipped", "reason": "not_auto_executable"}

            executed.append(
                ExecutedAction(
                    action_id=action.action_id,
                    situation_id=action.situation_id,
                    action_type=action.action_type.value,
                    vendor=action.vendor,
                    target=action.target,
                    status=result.get("status", "completed"),
                    result=result,
                    started_at=exec_start,
                    completed_at=datetime.now(UTC).isoformat(),
                )
            )
        except Exception as exc:
            executed.append(
                ExecutedAction(
                    action_id=action.action_id,
                    situation_id=action.situation_id,
                    action_type=action.action_type.value,
                    vendor=action.vendor,
                    target=action.target,
                    status="failed",
                    error=str(exc),
                    started_at=exec_start,
                    completed_at=datetime.now(UTC).isoformat(),
                )
            )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="execute_response",
        input_summary=f"Executing {len(auto_actions)} auto-approved actions",
        output_summary=f"Executed {len(executed)} actions",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="vendor_connectors",
    )

    return {
        "executed_actions": [*state.executed_actions, *executed],
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "execute_response",
    }


async def update_metrics(state: SOCBrainState) -> dict[str, Any]:
    """Track MTTD/MTTA/MTTR and finalize the workflow."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    # Record metrics
    await toolkit.record_metric("mttd_ms", float(state.mttd_ms))
    await toolkit.record_metric("mtta_ms", float(state.mtta_ms))
    await toolkit.record_metric("mttr_ms", float(duration_ms))
    await toolkit.record_metric("situations_created", float(len(state.situations_created)))
    await toolkit.record_metric("actions_executed", float(len(state.executed_actions)))

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="update_metrics",
        input_summary="Recording workflow metrics",
        output_summary=f"MTTD={state.mttd_ms}ms MTTA={state.mtta_ms}ms MTTR={duration_ms}ms",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="metrics_recorder",
    )

    return {
        "session_duration_ms": duration_ms,
        "mttr_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
