"""SOAR Workflow Orchestrator Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    AlertIntake,
    EnrichmentResult,
    ResponseAction,
    ResponseStage,
    ResponseStatus,
)
from .tools import SOARWorkflowToolkit

logger = structlog.get_logger()

# Module-level toolkit reference for node functions
_toolkit: SOARWorkflowToolkit | None = None


def set_toolkit(toolkit: SOARWorkflowToolkit) -> None:
    """Set the module-level toolkit for node functions."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> SOARWorkflowToolkit:
    """Get the module-level toolkit, creating a default if needed."""
    global _toolkit
    if _toolkit is None:
        _toolkit = SOARWorkflowToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state


async def intake_and_classify(
    state: dict[str, Any], toolkit: SOARWorkflowToolkit
) -> dict[str, Any]:
    """Intake, normalize, and classify an incoming security alert."""
    logger.info("soar_workflow.node.intake_and_classify")
    state = _to_dict(state)

    alert_data = state.get("alert", {})
    alert = await toolkit.intake_alert(alert_data)
    alert_dict = alert.model_dump()

    return {
        "stage": ResponseStage.ENRICH.value,
        "alert": alert_dict,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Ingested alert {alert.alert_id} from {alert.source} "
            f"(severity={alert.severity}, {len(alert.indicators)} indicators, "
            f"{len(alert.mitre_tactics)} MITRE tactics)"
        ],
    }


async def enrich_context(state: dict[str, Any], toolkit: SOARWorkflowToolkit) -> dict[str, Any]:
    """Enrich indicators from the alert with threat intelligence."""
    logger.info("soar_workflow.node.enrich_context")
    state = _to_dict(state)

    alert_data = state.get("alert", {})
    alert = AlertIntake(**alert_data)
    indicators = alert.indicators

    enrichments: list[dict[str, Any]] = []
    if indicators:
        results = await toolkit.enrich_indicators(indicators)
        enrichments = [r.model_dump() for r in results]

    malicious_count = sum(1 for e in enrichments if e.get("result", {}).get("is_malicious", False))

    reasoning_note = (
        f"Enriched {len(indicators)} indicators: {malicious_count} flagged as malicious"
    )

    # LLM enhancement: deeper enrichment analysis
    try:
        from .prompts import SYSTEM_ENRICH, EnrichmentAnalysisResult

        enrich_context = json.dumps(
            {
                "total_indicators": len(indicators),
                "malicious_count": malicious_count,
                "alert_severity": alert.severity,
                "mitre_tactics": alert.mitre_tactics,
                "enrichments_summary": [
                    {"indicator": e.get("indicator", ""), "is_malicious": e.get("result", {}).get("is_malicious", False)}
                    for e in enrichments[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            EnrichmentAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_ENRICH,
                user_prompt=f"Enrichment context:\n{enrich_context}",
                schema=EnrichmentAnalysisResult,
            ),
        )
        logger.info("llm_enhanced", agent="soar_workflow", node="enrich_context")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="soar_workflow", node="enrich_context")

    return {
        "stage": ResponseStage.CONTAIN.value,
        "enrichments": enrichments,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def execute_containment(
    state: dict[str, Any], toolkit: SOARWorkflowToolkit
) -> dict[str, Any]:
    """Execute containment actions based on enriched indicators."""
    logger.info("soar_workflow.node.execute_containment")
    state = _to_dict(state)

    enrichments = state.get("enrichments", [])
    actions: list[dict[str, Any]] = list(state.get("actions", []))
    total_duration = 0

    # Contain malicious indicators
    for enrichment_data in enrichments:
        enrichment = EnrichmentResult(**enrichment_data)
        if not enrichment.result.get("is_malicious", False):
            continue

        indicator_type = enrichment.result.get("indicator_type", "domain")
        action_type_map: dict[str, str] = {
            "ip": "block_ip",
            "domain": "block_ip",
            "hash": "isolate_host",
            "email": "disable_account",
        }
        action_type = action_type_map.get(indicator_type, "block_ip")
        action = await toolkit.execute_containment(enrichment.indicator, action_type)
        actions.append(action.model_dump())
        total_duration += action.duration_ms

    completed = sum(1 for a in actions if a.get("status") == ResponseStatus.COMPLETED.value)
    containment_status = "completed" if completed == len(actions) else "partial"
    if not actions:
        containment_status = "skipped"

    return {
        "stage": ResponseStage.ERADICATE.value,
        "actions": actions,
        "containment_status": containment_status,
        "total_response_time_ms": state.get("total_response_time_ms", 0) + total_duration,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Executed {len(actions)} containment actions: "
            f"{completed} completed, status={containment_status}"
        ],
    }


async def execute_eradication(
    state: dict[str, Any], toolkit: SOARWorkflowToolkit
) -> dict[str, Any]:
    """Execute eradication actions to remove the threat."""
    logger.info("soar_workflow.node.execute_eradication")
    state = _to_dict(state)

    alert_data = state.get("alert", {})
    alert = AlertIntake(**alert_data)
    actions: list[dict[str, Any]] = list(state.get("actions", []))
    total_duration = 0

    # Determine eradication actions based on MITRE tactics
    eradication_map: dict[str, str] = {
        "TA0002-Execution": "remove_malware",
        "TA0003-Persistence": "remove_malware",
        "TA0006-Credential Access": "rotate_credentials",
        "TA0004-Privilege Escalation": "rotate_credentials",
    }

    executed_types: set[str] = set()
    for tactic in alert.mitre_tactics:
        action_type = eradication_map.get(tactic, "patch_vulnerability")
        if action_type in executed_types:
            continue
        executed_types.add(action_type)

        target = alert.alert_id or "affected-system"
        action = await toolkit.execute_eradication(target, action_type)
        actions.append(action.model_dump())
        total_duration += action.duration_ms

    eradication_actions = [a for a in actions if a.get("playbook_type") == "eradication"]
    completed = sum(
        1 for a in eradication_actions if a.get("status") == ResponseStatus.COMPLETED.value
    )
    eradication_status = "completed" if completed == len(eradication_actions) else "partial"
    if not eradication_actions:
        eradication_status = "skipped"

    return {
        "stage": ResponseStage.RECOVER.value,
        "actions": actions,
        "eradication_status": eradication_status,
        "total_response_time_ms": state.get("total_response_time_ms", 0) + total_duration,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Executed {len(eradication_actions)} eradication actions: "
            f"{completed} completed, status={eradication_status}"
        ],
    }


async def recover_and_report(state: dict[str, Any], toolkit: SOARWorkflowToolkit) -> dict[str, Any]:
    """Execute recovery actions and generate the response report."""
    logger.info("soar_workflow.node.recover_and_report")
    state = _to_dict(state)

    alert_data = state.get("alert", {})
    alert = AlertIntake(**alert_data)
    actions: list[dict[str, Any]] = list(state.get("actions", []))
    total_duration = 0

    # Recovery: restore service, verify health, re-enable access
    recovery_types = ["restore_service", "verify_health", "reenable_access"]
    for action_type in recovery_types:
        target = alert.alert_id or "affected-system"
        action = await toolkit.execute_recovery(target, action_type)
        actions.append(action.model_dump())
        total_duration += action.duration_ms

    recovery_actions = [a for a in actions if a.get("playbook_type") == "recovery"]
    completed = sum(
        1 for a in recovery_actions if a.get("status") == ResponseStatus.COMPLETED.value
    )
    recovery_status = "completed" if completed == len(recovery_actions) else "partial"

    # Generate lessons learned
    lessons: list[str] = []
    all_actions = [ResponseAction(**a) for a in actions]
    failed_actions = [a for a in all_actions if a.status == ResponseStatus.FAILED]
    if failed_actions:
        lessons.append(f"{len(failed_actions)} action(s) failed — review playbook reliability")
    total_time = state.get("total_response_time_ms", 0) + total_duration
    lessons.append(f"Total response time: {total_time}ms")
    lessons.append(
        f"Response covered {len(alert.mitre_tactics)} MITRE tactics: "
        f"{', '.join(alert.mitre_tactics)}"
    )
    if total_time > 30000:
        lessons.append("Response time exceeded 30s SLA — investigate bottlenecks")

    return {
        "stage": ResponseStage.LESSONS_LEARNED.value,
        "actions": actions,
        "recovery_status": recovery_status,
        "total_response_time_ms": total_time,
        "lessons": lessons,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Recovery {recovery_status}: {completed}/{len(recovery_actions)} actions. "
            f"Total response time: {total_time}ms. "
            f"{len(lessons)} lessons documented."
        ],
    }
