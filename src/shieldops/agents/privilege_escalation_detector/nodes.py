"""Privilege Escalation Detector Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    EscalationEvent,
    EscalationFinding,
    EscalationStage,
    RiskAssessment,
)
from .tools import PrivilegeEscalationToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def collect_events(
    state: dict[str, Any],
    toolkit: PrivilegeEscalationToolkit,
) -> dict[str, Any]:
    """Collect privilege escalation events from all sources."""
    logger.info("privilege_escalation.node.collect_events")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    time_window = state.get("time_window_hours", 24)
    session_start = time.time()

    events = await toolkit.collect_escalation_events(
        tenant_id=tenant_id,
        time_window_hours=time_window,
    )
    event_dicts = [e.model_dump() for e in events]

    return {
        "escalation_events": event_dicts,
        "stage": EscalationStage.COLLECT_EVENTS.value,
        "session_start": session_start,
        "current_step": "collect_events",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Collected {len(events)} privilege escalation events for tenant {tenant_id}"],
    }


async def classify_escalations(
    state: dict[str, Any],
    toolkit: PrivilegeEscalationToolkit,
) -> dict[str, Any]:
    """Classify events into escalation findings."""
    logger.info("privilege_escalation.node.classify_escalations")
    state = _to_dict(state)
    raw_events = state.get("escalation_events", [])

    events = [EscalationEvent(**e) for e in raw_events]
    findings = await toolkit.classify_escalations(events)
    finding_dicts = [f.model_dump() for f in findings]

    reasoning_note = f"Classified {len(events)} events into {len(findings)} escalation findings"

    try:
        from .prompts import (
            SYSTEM_ESCALATION_CLASSIFICATION,
            EscalationClassificationOutput,
        )

        ctx = json.dumps(
            {
                "event_count": len(events),
                "finding_count": len(findings),
                "findings_summary": [
                    {
                        "type": f.escalation_type.value,
                        "principal": f.principal_id,
                        "confidence": f.confidence,
                        "mitre": f.mitre_technique,
                    }
                    for f in findings[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            EscalationClassificationOutput,
            await llm_structured(
                system_prompt=(SYSTEM_ESCALATION_CLASSIFICATION),
                user_prompt=(f"Escalation data:\n{ctx}"),
                schema=EscalationClassificationOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="privilege_escalation_detector",
            node="classify_escalations",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="privilege_escalation_detector",
            node="classify_escalations",
        )

    return {
        "escalation_findings": finding_dicts,
        "stage": (EscalationStage.CLASSIFY_ESCALATIONS.value),
        "current_step": "classify_escalations",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def correlate_identities(
    state: dict[str, Any],
    toolkit: PrivilegeEscalationToolkit,
) -> dict[str, Any]:
    """Correlate findings across identities and compute stats."""
    logger.info("privilege_escalation.node.correlate_identities")
    state = _to_dict(state)
    raw_findings = state.get("escalation_findings", [])

    sudo_count = 0
    role_change_count = 0
    iam_mod_count = 0
    sa_elevation_count = 0
    boundary_bypass_count = 0
    token_esc_count = 0

    for fd in raw_findings:
        etype = fd.get("escalation_type", "")
        if etype == "sudo_abuse":
            sudo_count += 1
        elif etype == "role_change":
            role_change_count += 1
        elif etype == "iam_policy_modification":
            iam_mod_count += 1
        elif etype == "service_account_elevation":
            sa_elevation_count += 1
        elif etype == "privilege_boundary_bypass":
            boundary_bypass_count += 1
        elif etype == "token_privilege_escalation":
            token_esc_count += 1

    stats = {
        "total_findings": len(raw_findings),
        "sudo_abuse_count": sudo_count,
        "role_change_count": role_change_count,
        "iam_modification_count": iam_mod_count,
        "sa_elevation_count": sa_elevation_count,
        "boundary_bypass_count": boundary_bypass_count,
        "token_escalation_count": token_esc_count,
        "high_confidence_count": sum(1 for f in raw_findings if f.get("confidence", 0) >= 0.85),
        "critical_count": sum(1 for f in raw_findings if f.get("confidence", 0) >= 0.9),
    }

    return {
        "stats": stats,
        "stage": (EscalationStage.CORRELATE_IDENTITIES.value),
        "current_step": "correlate_identities",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Correlation: {sudo_count} sudo abuse,"
            f" {role_change_count} role changes,"
            f" {iam_mod_count} IAM mods,"
            f" {sa_elevation_count} SA elevations,"
            f" {boundary_bypass_count} boundary bypasses"
        ],
    }


async def assess_risk(
    state: dict[str, Any],
    toolkit: PrivilegeEscalationToolkit,
) -> dict[str, Any]:
    """Assess risk for detected escalation findings."""
    logger.info("privilege_escalation.node.assess_risk")
    state = _to_dict(state)
    raw_findings = state.get("escalation_findings", [])

    findings = [EscalationFinding(**f) for f in raw_findings]
    assessments = await toolkit.assess_risk(findings)
    assessment_dicts = [a.model_dump() for a in assessments]

    reasoning_note = (
        f"Assessed risk for {len(findings)} findings:"
        f" {sum(a.blast_radius for a in assessments)}"
        f" total blast radius"
    )

    try:
        from .prompts import (
            SYSTEM_RISK_ASSESSMENT,
            RiskAssessmentOutput,
        )

        ctx = json.dumps(
            {
                "finding_count": len(findings),
                "assessments": [
                    {
                        "finding_id": a.finding_id,
                        "severity": a.severity.value,
                        "affected_resources": (a.affected_resources[:10]),
                        "blast_radius": a.blast_radius,
                        "containment_actions": (a.containment_actions),
                    }
                    for a in assessments[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            RiskAssessmentOutput,
            await llm_structured(
                system_prompt=SYSTEM_RISK_ASSESSMENT,
                user_prompt=f"Risk data:\n{ctx}",
                schema=RiskAssessmentOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="privilege_escalation_detector",
            node="assess_risk",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="privilege_escalation_detector",
            node="assess_risk",
        )

    return {
        "risk_assessments": assessment_dicts,
        "stage": EscalationStage.ASSESS_RISK.value,
        "current_step": "assess_risk",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def respond(
    state: dict[str, Any],
    toolkit: PrivilegeEscalationToolkit,
) -> dict[str, Any]:
    """Execute response actions for detected escalations."""
    logger.info("privilege_escalation.node.respond")
    state = _to_dict(state)
    raw_findings = state.get("escalation_findings", [])
    raw_assessments = state.get("risk_assessments", [])

    findings = [EscalationFinding(**f) for f in raw_findings]
    assessments = [RiskAssessment(**a) for a in raw_assessments]
    actions = await toolkit.execute_response(findings, assessments)
    action_dicts = [a.model_dump() for a in actions]

    reasoning_note = (
        f"Response: {len(actions)} actions,"
        f" {sum(1 for a in actions if a.auto_executed)}"
        f" auto-executed,"
        f" {sum(1 for a in actions if a.success)} successful"
    )

    try:
        from .prompts import (
            SYSTEM_RESPONSE_PLANNING,
            ResponsePlanOutput,
        )

        ctx = json.dumps(
            {
                "findings": [
                    {
                        "type": f.escalation_type.value,
                        "confidence": f.confidence,
                    }
                    for f in findings[:10]
                ],
                "actions_taken": [
                    {
                        "action_type": a.action_type,
                        "auto_executed": a.auto_executed,
                        "success": a.success,
                    }
                    for a in actions[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ResponsePlanOutput,
            await llm_structured(
                system_prompt=SYSTEM_RESPONSE_PLANNING,
                user_prompt=f"Response context:\n{ctx}",
                schema=ResponsePlanOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="privilege_escalation_detector",
            node="respond",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="privilege_escalation_detector",
            node="respond",
        )

    return {
        "response_actions": action_dicts,
        "stage": EscalationStage.RESPOND.value,
        "current_step": "respond",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: PrivilegeEscalationToolkit,
) -> dict[str, Any]:
    """Generate the final detection report."""
    logger.info("privilege_escalation.node.generate_report")
    state = _to_dict(state)
    session_start = state.get("session_start", time.time())
    duration_ms = (time.time() - session_start) * 1000

    findings = state.get("escalation_findings", [])
    assessments = state.get("risk_assessments", [])
    actions = state.get("response_actions", [])
    stats = state.get("stats", {})

    reasoning_note = (
        f"Report complete: {len(findings)} escalation"
        f" findings, {len(assessments)} risk assessments,"
        f" {len(actions)} response actions"
    )

    try:
        from .prompts import (
            SYSTEM_DETECTION_SUMMARY,
            DetectionSummaryOutput,
        )

        ctx = json.dumps(
            {
                "stats": stats,
                "finding_count": len(findings),
                "assessment_count": len(assessments),
                "action_count": len(actions),
                "findings_summary": [
                    {
                        "type": f.get("escalation_type", ""),
                        "confidence": f.get("confidence", 0),
                        "source": f.get("source_system", ""),
                        "mitre": f.get("mitre_technique", ""),
                    }
                    for f in findings[:10]
                ],
            },
            default=str,
        )
        llm_result = cast(
            DetectionSummaryOutput,
            await llm_structured(
                system_prompt=SYSTEM_DETECTION_SUMMARY,
                user_prompt=(f"Detection summary data:\n{ctx}"),
                schema=DetectionSummaryOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="privilege_escalation_detector",
            node="generate_report",
        )
        reasoning_note = f"{llm_result.executive_summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="privilege_escalation_detector",
            node="generate_report",
        )

    return {
        "stage": EscalationStage.REPORT.value,
        "current_step": "report",
        "session_duration_ms": round(duration_ms, 2),
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }
