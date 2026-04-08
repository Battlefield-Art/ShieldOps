"""Node implementations for the Autonomous SOC Agent."""

import contextlib
import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.autonomous_soc.models import (
    AnomalyDetection,
    AutomationLevel,
    AutonomousSOCState,
    IncidentCorrelation,
    IncidentPriority,
    OutcomeMeasurement,
    ReasoningStep,
    ResponseOrchestration,
    SecurityEvent,
    TriageDecision,
)
from shieldops.agents.autonomous_soc.prompts import (
    SYSTEM_ANOMALY_DETECTION,
    SYSTEM_AUTO_TRIAGE,
    SYSTEM_INCIDENT_CORRELATION,
    SYSTEM_RESPONSE_ORCHESTRATION,
    SYSTEM_SOC_REPORT,
    AnomalyAnalysisOutput,
    IncidentCorrelationOutput,
    ResponsePlanOutput,
    SOCReportOutput,
    TriageOutput,
)
from shieldops.agents.autonomous_soc.tools import (
    AutonomousSOCToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AutonomousSOCToolkit | None = None


def _get_toolkit() -> AutonomousSOCToolkit:
    if _toolkit is None:
        return AutonomousSOCToolkit()
    return _toolkit


async def ingest_events(
    state: AutonomousSOCState,
) -> dict[str, Any]:
    """Ingest security events from configured SIEMs."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    sources = state.siem_sources or [
        "splunk",
        "elastic",
        "sentinel",
    ]
    all_events: list[SecurityEvent] = []

    for siem in sources:
        try:
            if siem == "splunk":
                raw = await toolkit.ingest_from_splunk(
                    time_range_minutes=(state.time_range_minutes),
                )
            elif siem == "elastic":
                raw = await toolkit.ingest_from_elastic(
                    time_range_minutes=(state.time_range_minutes),
                )
            elif siem == "sentinel":
                raw = await toolkit.ingest_from_sentinel(
                    time_range_minutes=(state.time_range_minutes),
                )
            else:
                raw = []

            for event in raw:
                norm = await toolkit.normalize_siem_event(
                    siem,
                    event,
                )
                norm["ingested_at"] = datetime.now(UTC).isoformat()
                all_events.append(
                    SecurityEvent(**norm),
                )
        except Exception as exc:
            logger.warning(
                "autonomous_soc.ingest_failed",
                siem=siem,
                error=str(exc),
            )

    step = ReasoningStep(
        step_number=len(
            state.reasoning_chain,
        )
        + 1,
        action="ingest_events",
        input_summary=(f"Ingesting from {len(sources)} SIEMs"),
        output_summary=(f"Ingested {len(all_events)} events"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="siem_connectors",
    )

    return {
        "security_events": all_events,
        "events_processed": len(all_events),
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_stage": "ingest_events",
        "session_start": start,
    }


async def ml_detect_anomalies(
    state: AutonomousSOCState,
) -> dict[str, Any]:
    """Statistical + LLM hybrid anomaly detection."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    events_dicts = [e.model_dump() for e in state.security_events]

    # Phase 1: Statistical detection
    stat_anomalies = toolkit.detect_statistical_anomalies(
        events_dicts,
    )

    # Phase 2: LLM-enhanced analysis
    anomalies: list[AnomalyDetection] = []
    for raw_anom in stat_anomalies:
        llm_score = 0.0
        try:
            context = _json.dumps(
                {
                    "anomaly": raw_anom,
                    "event_count": len(
                        raw_anom.get(
                            "event_ids",
                            [],
                        ),
                    ),
                    "entities": raw_anom.get(
                        "affected_entities",
                        [],
                    ),
                },
                default=str,
            )
            llm_result = await llm_structured(
                system_prompt=(SYSTEM_ANOMALY_DETECTION),
                user_prompt=(f"Analyze anomaly:\n{context}"),
                schema=AnomalyAnalysisOutput,
            )
            llm_score = getattr(
                llm_result,
                "confidence",
                0.0,
            )
            raw_anom["anomaly_type"] = getattr(
                llm_result,
                "anomaly_type",
                raw_anom.get(
                    "anomaly_type",
                    "statistical",
                ),
            )
            raw_anom["description"] = getattr(
                llm_result,
                "description",
                raw_anom.get("description", ""),
            )
            raw_anom["is_anomalous"] = getattr(
                llm_result,
                "is_anomalous",
                True,
            )
            logger.info(
                "llm_enhanced",
                node="ml_detect_anomalies",
                anomaly_id=raw_anom.get(
                    "anomaly_id",
                ),
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="ml_detect_anomalies",
            )

        stat_score = raw_anom.get(
            "statistical_score",
            0.0,
        )
        combined = stat_score * 0.6 + llm_score * 0.4
        raw_anom["llm_score"] = llm_score
        raw_anom["combined_score"] = combined
        anomalies.append(
            AnomalyDetection(**raw_anom),
        )

    # Track MTTD
    mttd = 0.0
    if state.session_start:
        mttd = (datetime.now(UTC) - state.session_start).total_seconds()

    step = ReasoningStep(
        step_number=len(
            state.reasoning_chain,
        )
        + 1,
        action="ml_detect_anomalies",
        input_summary=(f"Analyzing {len(events_dicts)} events"),
        output_summary=(f"Detected {len(anomalies)} anomalies"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="statistical_detector+llm",
    )

    return {
        "anomalies": anomalies,
        "anomalies_detected": len(anomalies),
        "mean_time_to_detect_seconds": mttd,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_stage": "ml_detect_anomalies",
    }


async def correlate_incidents(
    state: AutonomousSOCState,
) -> dict[str, Any]:
    """Correlate anomalies into incidents."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    anom_dicts = [a.model_dump() for a in state.anomalies]
    raw_incidents = await toolkit.correlate_anomalies(anom_dicts)

    incidents: list[IncidentCorrelation] = []
    for raw_inc in raw_incidents:
        # LLM-enhanced correlation
        try:
            context = _json.dumps(
                {
                    "incident": raw_inc,
                    "anomaly_count": len(
                        raw_inc.get(
                            "anomaly_ids",
                            [],
                        ),
                    ),
                },
                default=str,
            )
            llm_result = await llm_structured(
                system_prompt=(SYSTEM_INCIDENT_CORRELATION),
                user_prompt=(f"Correlate incident:\n{context}"),
                schema=IncidentCorrelationOutput,
            )
            raw_inc["title"] = getattr(
                llm_result,
                "incident_title",
                raw_inc.get("title", ""),
            )
            raw_inc["description"] = getattr(
                llm_result,
                "incident_description",
                raw_inc.get("description", ""),
            )
            raw_inc["mitre_techniques"] = getattr(
                llm_result,
                "mitre_techniques",
                [],
            )
            raw_inc["kill_chain_phase"] = getattr(
                llm_result,
                "kill_chain_phase",
                "",
            )
            priority_str = getattr(
                llm_result,
                "priority",
                "p2_medium",
            )
            try:
                raw_inc["priority"] = IncidentPriority(priority_str)
            except ValueError:
                raw_inc["priority"] = IncidentPriority.P2_MEDIUM
            raw_inc["confidence"] = getattr(
                llm_result,
                "confidence",
                0.5,
            )
            logger.info(
                "llm_enhanced",
                node="correlate_incidents",
                incident_id=raw_inc.get(
                    "incident_id",
                ),
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="correlate_incidents",
            )
            raw_inc.setdefault(
                "priority",
                IncidentPriority.P2_MEDIUM,
            )

        raw_inc["siem_sources"] = list(
            {
                e.source_siem
                for e in state.security_events
                if e.event_id in raw_inc.get("event_ids", [])
            },
        )
        raw_inc["created_at"] = datetime.now(UTC).isoformat()
        incidents.append(
            IncidentCorrelation(**raw_inc),
        )

    step = ReasoningStep(
        step_number=len(
            state.reasoning_chain,
        )
        + 1,
        action="correlate_incidents",
        input_summary=(f"Correlating {len(anom_dicts)} anomalies"),
        output_summary=(f"Created {len(incidents)} incidents"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="correlation_engine+llm",
    )

    return {
        "incidents": incidents,
        "incidents_created": len(incidents),
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_stage": "correlate_incidents",
    }


async def auto_triage(
    state: AutonomousSOCState,
) -> dict[str, Any]:
    """Confidence-based auto-triage of incidents."""
    start = datetime.now(UTC)

    decisions: list[TriageDecision] = []
    auto_count = 0

    for incident in state.incidents:
        decision = TriageDecision(
            incident_id=incident.incident_id,
            priority=incident.priority,
            confidence=incident.confidence,
        )

        # LLM-powered triage
        try:
            context = _json.dumps(
                {
                    "incident_id": (incident.incident_id),
                    "title": incident.title,
                    "description": (incident.description),
                    "priority": incident.priority,
                    "mitre": (incident.mitre_techniques),
                    "kill_chain": (incident.kill_chain_phase),
                    "assets": (incident.affected_assets[:10]),
                    "confidence": (incident.confidence),
                    "siem_sources": (incident.siem_sources),
                },
                default=str,
            )
            llm_result = await llm_structured(
                system_prompt=SYSTEM_AUTO_TRIAGE,
                user_prompt=(f"Triage incident:\n{context}"),
                schema=TriageOutput,
            )
            conf = getattr(
                llm_result,
                "confidence",
                0.5,
            )
            decision.confidence = conf
            decision.reasoning = getattr(
                llm_result,
                "reasoning",
                "",
            )
            decision.recommended_playbook = getattr(
                llm_result,
                "recommended_playbook",
                "",
            )
            decision.escalation_needed = getattr(
                llm_result,
                "escalation_needed",
                False,
            )
            decision.escalation_reason = getattr(
                llm_result,
                "escalation_reason",
                "",
            )
            decision.estimated_impact = getattr(
                llm_result,
                "estimated_impact",
                "",
            )

            # Priority from LLM
            with contextlib.suppress(ValueError):
                decision.priority = IncidentPriority(
                    getattr(llm_result, "priority", "p2_medium"),
                )

            # Automation level by confidence
            auto_level_str = getattr(
                llm_result,
                "automation_level",
                "",
            )
            try:
                decision.automation_level = AutomationLevel(auto_level_str)
            except ValueError:
                if conf > 0.95:
                    decision.automation_level = AutomationLevel.FULLY_AUTONOMOUS
                elif conf > 0.80:
                    decision.automation_level = AutomationLevel.SUPERVISED
                else:
                    decision.automation_level = AutomationLevel.MANUAL

            if decision.automation_level in (
                AutomationLevel.FULLY_AUTONOMOUS,
                AutomationLevel.SUPERVISED,
            ):
                auto_count += 1

            logger.info(
                "llm_enhanced",
                node="auto_triage",
                incident_id=(incident.incident_id),
                automation=decision.automation_level,
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="auto_triage",
            )
            # Fallback: confidence-based automation
            if incident.confidence > 0.95:
                decision.automation_level = AutomationLevel.FULLY_AUTONOMOUS
                auto_count += 1
            elif incident.confidence > 0.80:
                decision.automation_level = AutomationLevel.SUPERVISED
                auto_count += 1
            else:
                decision.automation_level = AutomationLevel.MANUAL

        decisions.append(decision)

    step = ReasoningStep(
        step_number=len(
            state.reasoning_chain,
        )
        + 1,
        action="auto_triage",
        input_summary=(f"Triaging {len(state.incidents)} incidents"),
        output_summary=(f"Triaged {len(decisions)}, {auto_count} automated"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )

    return {
        "triage_decisions": decisions,
        "auto_triaged": auto_count,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_stage": "auto_triage",
    }


async def orchestrate_response(
    state: AutonomousSOCState,
) -> dict[str, Any]:
    """Orchestrate multi-step response for triaged incidents."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    responses: list[ResponseOrchestration] = []
    from uuid import uuid4

    for decision in state.triage_decisions:
        if decision.automation_level == (AutomationLevel.DISABLED):
            continue

        # Find matching incident
        incident = next(
            (i for i in state.incidents if i.incident_id == decision.incident_id),
            None,
        )
        if not incident:
            continue

        resp = ResponseOrchestration(
            response_id=f"resp-{uuid4().hex[:12]}",
            incident_id=decision.incident_id,
            automation_level=(decision.automation_level),
            started_at=(datetime.now(UTC).isoformat()),
        )

        # LLM-powered response planning
        try:
            context = _json.dumps(
                {
                    "incident_id": (incident.incident_id),
                    "title": incident.title,
                    "priority": decision.priority,
                    "automation_level": (decision.automation_level),
                    "playbook": (decision.recommended_playbook),
                    "mitre": (incident.mitre_techniques),
                    "assets": (incident.affected_assets[:5]),
                    "siem_sources": (incident.siem_sources),
                },
                default=str,
            )
            llm_result = await llm_structured(
                system_prompt=(SYSTEM_RESPONSE_ORCHESTRATION),
                user_prompt=(f"Plan response:\n{context}"),
                schema=ResponsePlanOutput,
            )
            resp.playbook_name = getattr(
                llm_result,
                "playbook_name",
                "",
            )
            all_steps = getattr(
                llm_result,
                "steps",
                [],
            )
            auto_indices = set(
                getattr(
                    llm_result,
                    "automation_safe",
                    [],
                ),
            )

            # Execute auto-safe steps
            executed_steps: list[dict[str, Any]] = []
            pending_steps: list[dict[str, Any]] = []

            for idx, s in enumerate(all_steps):
                if idx in auto_indices and (
                    decision.automation_level
                    in (
                        AutomationLevel.FULLY_AUTONOMOUS,
                        AutomationLevel.SUPERVISED,
                    )
                ):
                    result = await toolkit.execute_response_step(
                        s,
                        incident.incident_id,
                    )
                    executed_steps.append(
                        {**s, "result": result},
                    )
                else:
                    pending_steps.append(s)

            resp.steps_executed = executed_steps
            resp.steps_pending = pending_steps
            resp.status = "completed" if not pending_steps else "partial"

            logger.info(
                "llm_enhanced",
                node="orchestrate_response",
                incident_id=(incident.incident_id),
                executed=len(executed_steps),
                pending=len(pending_steps),
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="orchestrate_response",
            )
            resp.status = "pending"

        resp.completed_at = datetime.now(UTC).isoformat()
        responses.append(resp)

    step = ReasoningStep(
        step_number=len(
            state.reasoning_chain,
        )
        + 1,
        action="orchestrate_response",
        input_summary=(f"Orchestrating {len(state.triage_decisions)} decisions"),
        output_summary=(f"Orchestrated {len(responses)} responses"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="soar_engine+llm",
    )

    return {
        "responses": responses,
        "responses_orchestrated": len(responses),
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_stage": "orchestrate_response",
    }


async def measure_outcomes(
    state: AutonomousSOCState,
) -> dict[str, Any]:
    """Measure MTTD, MTTR, automation rate, and FP rate."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()
    from uuid import uuid4

    outcomes: list[OutcomeMeasurement] = []
    mttr = 0.0
    if state.session_start:
        mttr = (datetime.now(UTC) - state.session_start).total_seconds()

    total_incidents = len(state.incidents)
    auto_count = sum(
        1
        for d in state.triage_decisions
        if d.automation_level
        in (
            AutomationLevel.FULLY_AUTONOMOUS,
            AutomationLevel.SUPERVISED,
        )
    )
    auto_rate = auto_count / total_incidents if total_incidents > 0 else 0.0

    for incident in state.incidents:
        decision = next(
            (d for d in state.triage_decisions if d.incident_id == incident.incident_id),
            None,
        )
        outcome = OutcomeMeasurement(
            measurement_id=(f"meas-{uuid4().hex[:12]}"),
            incident_id=incident.incident_id,
            mttd_seconds=(state.mean_time_to_detect_seconds),
            mttr_seconds=mttr,
            automation_rate=auto_rate,
            false_positive=False,
            analyst_override=decision is not None
            and decision.automation_level == AutomationLevel.MANUAL,
            outcome_category=(
                "automated"
                if decision
                and decision.automation_level
                in (
                    AutomationLevel.FULLY_AUTONOMOUS,
                    AutomationLevel.SUPERVISED,
                )
                else "manual"
            ),
        )
        outcomes.append(outcome)

    # Record metrics
    await toolkit.record_soc_metric(
        "mttd_seconds",
        state.mean_time_to_detect_seconds,
    )
    await toolkit.record_soc_metric(
        "mttr_seconds",
        mttr,
    )
    await toolkit.record_soc_metric(
        "automation_rate",
        auto_rate,
    )
    await toolkit.record_soc_metric(
        "events_processed",
        float(state.events_processed),
    )
    await toolkit.record_soc_metric(
        "anomalies_detected",
        float(state.anomalies_detected),
    )
    await toolkit.record_soc_metric(
        "incidents_created",
        float(state.incidents_created),
    )

    step = ReasoningStep(
        step_number=len(
            state.reasoning_chain,
        )
        + 1,
        action="measure_outcomes",
        input_summary="Measuring SOC outcomes",
        output_summary=(
            f"MTTD={state.mean_time_to_detect_seconds:.1f}s MTTR={mttr:.1f}s auto={auto_rate:.0%}"
        ),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="metrics_store",
    )

    return {
        "outcomes": outcomes,
        "mean_time_to_respond_seconds": mttr,
        "automation_rate": auto_rate,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_stage": "measure_outcomes",
    }


async def report(
    state: AutonomousSOCState,
) -> dict[str, Any]:
    """Generate SOC shift report."""
    start = datetime.now(UTC)

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report_data: dict[str, Any] = {
        "tenant_id": state.tenant_id,
        "events_processed": state.events_processed,
        "anomalies_detected": (state.anomalies_detected),
        "incidents_created": state.incidents_created,
        "auto_triaged": state.auto_triaged,
        "responses_orchestrated": (state.responses_orchestrated),
        "mttd_seconds": (state.mean_time_to_detect_seconds),
        "mttr_seconds": (state.mean_time_to_respond_seconds),
        "automation_rate": state.automation_rate,
        "siem_sources": state.siem_sources,
        "duration_ms": duration_ms,
    }

    # LLM-generated executive summary
    try:
        context = _json.dumps(
            report_data,
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_SOC_REPORT,
            user_prompt=(f"Generate SOC report:\n{context}"),
            schema=SOCReportOutput,
        )
        report_data["executive_summary"] = getattr(
            llm_result,
            "executive_summary",
            "",
        )
        report_data["key_incidents"] = getattr(
            llm_result,
            "key_incidents",
            [],
        )
        report_data["automation_highlights"] = getattr(
            llm_result,
            "automation_highlights",
            "",
        )
        report_data["improvement_recommendations"] = getattr(
            llm_result,
            "improvement_recommendations",
            [],
        )
        report_data["risk_posture"] = getattr(
            llm_result,
            "risk_posture",
            "",
        )
        logger.info(
            "llm_enhanced",
            node="report",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="report",
        )
        report_data["executive_summary"] = (
            f"Processed {state.events_processed} "
            f"events, detected "
            f"{state.anomalies_detected} anomalies, "
            f"created {state.incidents_created} "
            f"incidents. Automation rate: "
            f"{state.automation_rate:.0%}."
        )

    step = ReasoningStep(
        step_number=len(
            state.reasoning_chain,
        )
        + 1,
        action="report",
        input_summary="Generating SOC report",
        output_summary="Report generated",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )

    return {
        "report": report_data,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_stage": "complete",
    }
