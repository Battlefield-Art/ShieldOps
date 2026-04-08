"""Node implementations for the Autonomous Response
Engine Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.autonomous_response_engine.models import (
    AREStage,
    AutonomousResponseEngineState,
    IncidentSeverity,
    ReasoningStep,
)
from shieldops.agents.autonomous_response_engine.prompts import (
    SYSTEM_CLASSIFICATION,
    SYSTEM_DETECTION,
    SYSTEM_PLAYBOOK,
    SYSTEM_REPORT,
    IncidentDetectionOutput,
    PlaybookSelectionOutput,
    ResponseReportOutput,
    SeverityClassificationOutput,
)
from shieldops.agents.autonomous_response_engine.tools import (
    AutonomousResponseEngineToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AutonomousResponseEngineToolkit | None = None


def _get_toolkit() -> AutonomousResponseEngineToolkit:
    if _toolkit is None:
        return AutonomousResponseEngineToolkit()
    return _toolkit


def _step(
    chain: list[ReasoningStep],
    action: str,
    input_summary: str,
    output_summary: str,
    start: datetime,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Build a reasoning step with duration."""
    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return ReasoningStep(
        step_number=len(chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=elapsed,
        tool_used=tool_used,
    )


# ------------------------------------------------------------------
# Node: detect_incident
# ------------------------------------------------------------------


async def detect_incident(
    state: AutonomousResponseEngineState,
) -> dict[str, Any]:
    """Detect and correlate incidents from incoming
    alert data."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.detect_incident(
        alert_source=state.alert_source,
        alert_data=state.alert_data,
    )

    detections: list[dict[str, Any]] = list(results)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "incident_name": state.incident_name,
                "alert_source": state.alert_source,
                "alert_data": state.alert_data,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_DETECTION,
            user_prompt=(f"Analyze alert data:\n{ctx}"),
            schema=IncidentDetectionOutput,
        )
        if llm_out.incidents:  # type: ignore[union-attr]
            detections = [
                *detections,
                *llm_out.incidents,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="detect_incident",
            count=len(llm_out.incidents),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_incident",
        )

    step = _step(
        state.reasoning_chain,
        "detect_incident",
        f"Source: {state.alert_source}",
        f"Detected {len(detections)} incidents",
        start,
        "siem_client",
    )

    return {
        "detections": detections,
        "stage": AREStage.DETECT_INCIDENT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_incident",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: classify_severity
# ------------------------------------------------------------------


async def classify_severity(
    state: AutonomousResponseEngineState,
) -> dict[str, Any]:
    """Classify incident severity based on context and
    business impact."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    classifications = await toolkit.classify_severity(
        detections=state.detections,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "detection_count": len(state.detections),
                "detections_sample": state.detections[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_CLASSIFICATION,
            user_prompt=(f"Classify severity:\n{ctx}"),
            schema=SeverityClassificationOutput,
        )
        if llm_out.severity:  # type: ignore[union-attr]
            classifications.append(
                {
                    "classification_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "severity": llm_out.severity,  # type: ignore[union-attr]
                    "business_impact": llm_out.business_impact,  # type: ignore[union-attr]
                    "data_at_risk": llm_out.data_at_risk,  # type: ignore[union-attr]
                    "rationale": llm_out.rationale,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="classify_severity",
            severity=llm_out.severity,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="classify_severity",
        )

    # Determine highest severity
    _severity_order = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "informational": 0,
    }
    max_sev = "medium"
    for c in classifications:
        sev = c.get("severity", "medium")
        if _severity_order.get(sev, 0) > _severity_order.get(max_sev, 0):
            max_sev = sev

    step = _step(
        state.reasoning_chain,
        "classify_severity",
        f"Classifying {len(state.detections)} detections",
        f"Severity: {max_sev}",
        start,
        "severity_classifier",
    )

    return {
        "classifications": classifications,
        "severity": IncidentSeverity(max_sev),
        "stage": AREStage.CLASSIFY_SEVERITY,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "classify_severity",
    }


# ------------------------------------------------------------------
# Node: select_playbook
# ------------------------------------------------------------------


async def select_playbook(
    state: AutonomousResponseEngineState,
) -> dict[str, Any]:
    """Select the optimal response playbook for the
    classified incident."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    selected = await toolkit.select_playbook(
        classifications=state.classifications,
        severity=state.severity.value,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "severity": state.severity.value,
                "classifications": state.classifications[:5],
                "detections": state.detections[:3],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_PLAYBOOK,
            user_prompt=(f"Select playbook:\n{ctx}"),
            schema=PlaybookSelectionOutput,
        )
        if llm_out.playbook_name:  # type: ignore[union-attr]
            selected.update(
                {
                    "playbook_name": llm_out.playbook_name,  # type: ignore[union-attr]
                    "response_actions": llm_out.response_actions,  # type: ignore[union-attr]
                    "estimated_time": llm_out.estimated_time,  # type: ignore[union-attr]
                    "requires_approval": llm_out.requires_approval,  # type: ignore[union-attr]
                    "rationale": llm_out.rationale,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="select_playbook",
            playbook=llm_out.playbook_name,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="select_playbook",
        )

    step = _step(
        state.reasoning_chain,
        "select_playbook",
        f"Severity: {state.severity.value}",
        f"Selected: {selected.get('playbook_name', 'unknown')}",
        start,
        "playbook_store",
    )

    return {
        "selected_playbook": selected,
        "stage": AREStage.SELECT_PLAYBOOK,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "select_playbook",
    }


# ------------------------------------------------------------------
# Node: execute_response
# ------------------------------------------------------------------


async def execute_response(
    state: AutonomousResponseEngineState,
) -> dict[str, Any]:
    """Execute response actions from the selected
    playbook."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    executions = await toolkit.execute_response(
        playbook=state.selected_playbook,
        auto_execute=state.auto_execute,
    )

    actions_taken = sum(1 for e in executions if e.get("success", False))

    step = _step(
        state.reasoning_chain,
        "execute_response",
        f"Playbook: {state.selected_playbook.get('playbook_name', 'unknown')}",
        f"Executed {actions_taken} of {len(executions)} actions",
        start,
        "containment_engine",
    )

    return {
        "executions": executions,
        "actions_taken": actions_taken,
        "stage": AREStage.EXECUTE_RESPONSE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "execute_response",
    }


# ------------------------------------------------------------------
# Node: validate_outcome
# ------------------------------------------------------------------


async def validate_outcome(
    state: AutonomousResponseEngineState,
) -> dict[str, Any]:
    """Validate response outcomes and confirm threat
    containment."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    validations = await toolkit.validate_outcome(
        executions=state.executions,
        detections=state.detections,
    )

    contained = any(v.get("threat_contained", False) for v in validations)

    step = _step(
        state.reasoning_chain,
        "validate_outcome",
        f"Validating {len(state.executions)} executions",
        f"Contained: {contained}",
        start,
        "validation_engine",
    )

    return {
        "validations": validations,
        "threat_contained": contained,
        "stage": AREStage.VALIDATE_OUTCOME,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "validate_outcome",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: AutonomousResponseEngineState,
) -> dict[str, Any]:
    """Generate the final incident response report with
    executive summary and lessons learned."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    report: dict[str, Any] = {
        "incident_name": state.incident_name,
        "severity": state.severity.value,
        "threat_contained": state.threat_contained,
        "actions_taken": state.actions_taken,
        "response_time_ms": duration_ms,
    }

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "incident_name": state.incident_name,
                "severity": state.severity.value,
                "detections": state.detections[:5],
                "classifications": state.classifications[:3],
                "playbook": state.selected_playbook,
                "executions": state.executions[:5],
                "validations": state.validations[:3],
                "threat_contained": state.threat_contained,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate response report:\n{ctx}"),
            schema=ResponseReportOutput,
        )
        if isinstance(llm_out, ResponseReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "actions_summary": llm_out.actions_summary,
                    "recommendations": llm_out.recommendations,
                    "lessons_learned": llm_out.lessons_learned,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                recommendations=len(llm_out.recommendations),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    # Record metrics
    await toolkit.record_metric(
        incident_id=state.request_id,
        outcome={
            "severity": state.severity.value,
            "threat_contained": state.threat_contained,
            "actions_taken": state.actions_taken,
            "response_time_ms": duration_ms,
        },
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        (f"Reporting on {state.severity.value} incident"),
        (f"Report generated, contained={state.threat_contained}"),
        start,
        "report_generator",
    )

    return {
        "report": report,
        "response_time_ms": duration_ms,
        "session_duration_ms": duration_ms,
        "stage": AREStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
