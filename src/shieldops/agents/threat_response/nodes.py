"""Threat Response Agent — Node function implementations."""

from __future__ import annotations

import contextlib
import json
from typing import Any, cast

import structlog

from shieldops.utils.llm import llm_structured

from .models import (
    ActionStatus,
    ContainmentAction,
    EradicationAction,
    ResponseStage,
    ThreatIndicator,
    ThreatSeverity,
)
from .prompts import (
    SYSTEM_CLASSIFY,
    SYSTEM_PLAYBOOK,
    SYSTEM_REPORT,
    PlaybookSelectionResult,
    ResponseReportResult,
    ThreatClassificationResult,
)
from .tools import ThreatResponseToolkit

logger = structlog.get_logger()


async def classify_threat(state: dict[str, Any], toolkit: ThreatResponseToolkit) -> dict[str, Any]:
    """Classify the incoming threat."""
    logger.info("threat_response.node.classify")

    raw_indicators = state.get("threat_indicators", [])
    indicators = [ThreatIndicator(**i) for i in raw_indicators]
    threat_type, severity = await toolkit.classify_threat(indicators)

    reasoning_note = (
        f"Classified threat as '{threat_type}' with severity '{severity.value}' "
        f"from {len(indicators)} indicators"
    )

    if indicators:
        try:
            context = json.dumps(
                {
                    "indicators": [
                        {
                            "type": i.indicator_type,
                            "value": i.value[:50],
                            "severity": i.severity,
                            "mitre_tactic": i.mitre_tactic,
                        }
                        for i in indicators[:10]
                    ],
                },
                default=str,
            )
            result = cast(
                ThreatClassificationResult,
                await llm_structured(
                    system_prompt=SYSTEM_CLASSIFY,
                    user_prompt=f"Threat indicators:\n{context}",
                    schema=ThreatClassificationResult,
                ),
            )
            threat_type = result.threat_type or threat_type
            severity_str = result.severity or severity.value
            with contextlib.suppress(ValueError):
                severity = ThreatSeverity(severity_str)
            reasoning_note = f"{result.summary}. {reasoning_note}"
        except Exception:
            logger.debug("llm_fallback", agent="threat_response", node="classify")

    return {
        "stage": ResponseStage.SELECT_PLAYBOOK.value,
        "threat_classification": threat_type,
        "threat_severity": severity.value,
        "total_indicators": len(indicators),
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def select_playbook(state: dict[str, Any], toolkit: ThreatResponseToolkit) -> dict[str, Any]:
    """Select the appropriate response playbook."""
    logger.info("threat_response.node.select_playbook")

    threat_type = state.get("threat_classification", "unknown")
    severity_str = state.get("threat_severity", "medium")
    try:
        severity = ThreatSeverity(severity_str)
    except ValueError:
        severity = ThreatSeverity.MEDIUM

    playbook = await toolkit.select_playbook(threat_type, severity)
    playbook_data = playbook.model_dump()

    reasoning_note = (
        f"Selected playbook: {playbook.name} "
        f"({len(playbook.steps)} steps, "
        f"est. {playbook.estimated_time_min} min)"
    )

    try:
        context = json.dumps(
            {
                "threat_type": threat_type,
                "severity": severity_str,
                "playbook": playbook.name,
                "steps": playbook.steps,
            },
            default=str,
        )
        result = cast(
            PlaybookSelectionResult,
            await llm_structured(
                system_prompt=SYSTEM_PLAYBOOK,
                user_prompt=f"Playbook selection context:\n{context}",
                schema=PlaybookSelectionResult,
            ),
        )
        reasoning_note = f"{result.summary}. {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="threat_response", node="playbook")

    return {
        "stage": ResponseStage.EXECUTE_CONTAINMENT.value,
        "selected_playbook": playbook_data,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def execute_containment(
    state: dict[str, Any], toolkit: ThreatResponseToolkit
) -> dict[str, Any]:
    """Execute containment actions."""
    logger.info("threat_response.node.containment")

    threat_type = state.get("threat_classification", "unknown")
    raw_indicators = state.get("threat_indicators", [])
    indicators = [ThreatIndicator(**i) for i in raw_indicators]

    actions = await toolkit.execute_containment(threat_type, indicators)
    actions_data = [a.model_dump(mode="json") for a in actions]

    completed = sum(1 for a in actions if a.status == ActionStatus.COMPLETED)
    contained = completed == len(actions) and len(actions) > 0

    return {
        "stage": ResponseStage.EXECUTE_ERADICATION.value,
        "containment_actions": actions_data,
        "threat_contained": contained,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Executed {len(actions)} containment actions, {completed} completed"],
    }


async def execute_eradication(
    state: dict[str, Any], toolkit: ThreatResponseToolkit
) -> dict[str, Any]:
    """Execute eradication actions."""
    logger.info("threat_response.node.eradication")

    threat_type = state.get("threat_classification", "unknown")
    raw_containment = state.get("containment_actions", [])
    containment = [ContainmentAction(**a) for a in raw_containment]

    actions = await toolkit.execute_eradication(threat_type, containment)
    actions_data = [a.model_dump(mode="json") for a in actions]

    return {
        "stage": ResponseStage.VERIFY_REMEDIATION.value,
        "eradication_actions": actions_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Executed {len(actions)} eradication actions"],
    }


async def verify_remediation(
    state: dict[str, Any], toolkit: ThreatResponseToolkit
) -> dict[str, Any]:
    """Verify remediation effectiveness."""
    logger.info("threat_response.node.verify")

    raw_containment = state.get("containment_actions", [])
    raw_eradication = state.get("eradication_actions", [])
    containment = [ContainmentAction(**a) for a in raw_containment]
    eradication = [EradicationAction(**a) for a in raw_eradication]

    verifications = await toolkit.verify_remediation(containment, eradication)
    verifications_data = [v.model_dump(mode="json") for v in verifications]

    verified_count = sum(1 for v in verifications if v.verified)
    total_actions = len(containment) + len(eradication)

    return {
        "stage": ResponseStage.REPORT.value,
        "verifications": verifications_data,
        "actions_completed": verified_count,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Verified {verified_count}/{total_actions} actions"],
    }


async def generate_report(state: dict[str, Any], toolkit: ThreatResponseToolkit) -> dict[str, Any]:
    """Generate threat response report."""
    logger.info("threat_response.node.report")

    threat_type = state.get("threat_classification", "unknown")
    severity = state.get("threat_severity", "unknown")
    total_indicators = state.get("total_indicators", 0)
    actions_completed = state.get("actions_completed", 0)
    contained = state.get("threat_contained", False)

    summary = (
        f"Responded to {threat_type} threat ({severity}): "
        f"{total_indicators} indicators, {actions_completed} actions completed, "
        f"contained={contained}"
    )

    try:
        context = json.dumps(
            {
                "threat_type": threat_type,
                "severity": severity,
                "total_indicators": total_indicators,
                "containment_actions": len(state.get("containment_actions", [])),
                "eradication_actions": len(state.get("eradication_actions", [])),
                "actions_completed": actions_completed,
                "threat_contained": contained,
            },
            default=str,
        )
        result = cast(
            ResponseReportResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Response report context:\n{context}",
                schema=ResponseReportResult,
            ),
        )
        summary = result.executive_summary
    except Exception:
        logger.debug("llm_fallback", agent="threat_response", node="report")

    return {
        "stage": ResponseStage.REPORT.value,
        "summary": summary,
        "reasoning_chain": state.get("reasoning_chain", []) + [summary],
    }
