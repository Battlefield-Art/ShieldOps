"""Node implementations for the Incident Escalation Engine."""

from __future__ import annotations

import json as _json
import time
from typing import Any

import structlog

from shieldops.utils.llm import llm_structured

from .models import IEEStage
from .prompts import (
    SYSTEM_ANALYZE,
    SYSTEM_REPORT,
    AnalyzeOutput,
    ReportOutput,
)
from .tools import IncidentEscalationEngineToolkit

logger = structlog.get_logger()

_toolkit: IncidentEscalationEngineToolkit | None = None


def _get_toolkit() -> IncidentEscalationEngineToolkit:
    if _toolkit is None:
        return IncidentEscalationEngineToolkit()
    return _toolkit


async def assess_severity(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Assess incident severity and urgency."""
    start = time.time()
    tk = _get_toolkit()

    result = await tk.assess_severity(
        title=state.get("incident_title", ""),
        description=state.get("incident_description", ""),
        severity_raw=state.get("severity_raw", ""),
        affected_services=state.get(
            "affected_services",
            [],
        ),
        alert_count=state.get("alert_count", 0),
    )

    try:
        ctx = _json.dumps(
            {
                "title": state.get("incident_title", ""),
                "description": state.get(
                    "incident_description",
                    "",
                ),
                "services": state.get(
                    "affected_services",
                    [],
                ),
                "alerts": state.get("alert_count", 0),
            },
            default=str,
        )
        llm = await llm_structured(
            system_prompt=SYSTEM_ANALYZE,
            user_prompt=f"Assess this incident:\n{ctx}",
            schema=AnalyzeOutput,
        )
        if hasattr(llm, "urgency") and llm.urgency:
            result["llm_urgency"] = llm.urgency
        if hasattr(llm, "reasoning") and llm.reasoning:
            result["llm_reasoning"] = llm.reasoning
    except Exception:
        logger.debug("iesc.llm_skipped", node="assess")

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "assess_severity",
        "stage": IEEStage.EVALUATE_IMPACT.value,
        "severity_assessment": result,
        "reasoning_chain": [
            *chain,
            {
                "step": "assess_severity",
                "detail": f"Urgency={result.get('urgency')}",
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "assess_ms": elapsed,
        },
    }


async def evaluate_impact(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Evaluate business impact."""
    start = time.time()
    tk = _get_toolkit()

    result = await tk.evaluate_impact(
        severity_assessment=state.get(
            "severity_assessment",
            {},
        ),
        affected_services=state.get(
            "affected_services",
            [],
        ),
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "evaluate_impact",
        "stage": IEEStage.DETERMINE_ESCALATION.value,
        "impact_evaluation": result,
        "reasoning_chain": [
            *chain,
            {
                "step": "evaluate_impact",
                "detail": f"Blast={result.get('blast_radius')}",
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "impact_ms": elapsed,
        },
    }


async def determine_escalation(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Determine escalation tier and path."""
    start = time.time()
    tk = _get_toolkit()

    result = await tk.determine_escalation(
        severity_assessment=state.get(
            "severity_assessment",
            {},
        ),
        impact_evaluation=state.get(
            "impact_evaluation",
            {},
        ),
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "determine_escalation",
        "stage": IEEStage.NOTIFY_RESPONDERS.value,
        "escalation_decision": result,
        "reasoning_chain": [
            *chain,
            {
                "step": "determine_escalation",
                "detail": f"Tier={result.get('tier')}",
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "escalation_ms": elapsed,
        },
    }


async def notify_responders(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Send escalation notifications."""
    start = time.time()
    tk = _get_toolkit()

    notes = await tk.notify_responders(
        escalation_decision=state.get(
            "escalation_decision",
            {},
        ),
        incident_id=state.get("incident_id", ""),
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "notify_responders",
        "stage": IEEStage.TRACK_RESPONSE.value,
        "notifications_sent": notes,
        "reasoning_chain": [
            *chain,
            {
                "step": "notify_responders",
                "detail": f"Sent {len(notes)} notifications",
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "notify_ms": elapsed,
        },
    }


async def track_response(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Track responder acknowledgments."""
    start = time.time()
    tk = _get_toolkit()

    result = await tk.track_response(
        notifications_sent=state.get(
            "notifications_sent",
            [],
        ),
        escalation_decision=state.get(
            "escalation_decision",
            {},
        ),
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "track_response",
        "stage": IEEStage.REPORT.value,
        "response_tracking": result,
        "reasoning_chain": [
            *chain,
            {
                "step": "track_response",
                "detail": f"Acked={result.get('acknowledged')}",
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "track_ms": elapsed,
        },
    }


async def report(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Generate escalation summary report."""
    start = time.time()
    report_data: dict[str, Any] = {
        "severity_assessment": state.get(
            "severity_assessment",
            {},
        ),
        "impact_evaluation": state.get(
            "impact_evaluation",
            {},
        ),
        "escalation_decision": state.get(
            "escalation_decision",
            {},
        ),
        "notifications": len(
            state.get("notifications_sent", []),
        ),
        "response_tracking": state.get(
            "response_tracking",
            {},
        ),
    }

    try:
        ctx = _json.dumps(report_data, default=str)
        llm = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate report:\n{ctx}",
            schema=ReportOutput,
        )
        if hasattr(llm, "executive_summary"):
            report_data["executive_summary"] = llm.executive_summary
            report_data["key_decisions"] = llm.key_decisions
            report_data["recommended_actions"] = llm.recommended_actions
    except Exception:
        logger.debug("iesc.llm_skipped", node="report")

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "report",
        "stage": IEEStage.REPORT.value,
        "stats": {
            **state.get("stats", {}),
            **report_data,
            "report_ms": elapsed,
        },
        "reasoning_chain": [
            *chain,
            {
                "step": "report",
                "detail": "Escalation report generated",
                "elapsed_ms": elapsed,
            },
        ],
    }
