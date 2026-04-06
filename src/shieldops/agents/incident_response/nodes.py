"""Node implementations for the Incident Response Agent LangGraph workflow."""

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.incident_response.models import (
    ContainmentAction,
    EradicationStep,
    IncidentResponseState,
    RecoveryTask,
    ResponseReasoningStep,
)
from shieldops.agents.incident_response.prompts import (
    SYSTEM_ASSESS,
    SYSTEM_TIMELINE,
    AssessmentOutput,
    TimelineSummaryOutput,
)
from shieldops.agents.incident_response.tools import IncidentResponseToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: IncidentResponseToolkit | None = None


def set_toolkit(toolkit: IncidentResponseToolkit) -> None:
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> IncidentResponseToolkit:
    if _toolkit is None:
        return IncidentResponseToolkit()
    return _toolkit


async def assess_incident(state: IncidentResponseState) -> dict[str, Any]:
    """Perform initial incident assessment and severity classification."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    incident_data = state.incident_data
    severity_input = incident_data.get("severity", "medium")

    severity_scores = {"critical": 95, "high": 80, "medium": 50, "low": 25}
    assessment_score = float(severity_scores.get(severity_input, 50))

    incident_type = incident_data.get("type", "unknown")

    # LLM enhancement: deeper incident assessment reasoning
    try:
        import json as _json

        assess_context = _json.dumps(
            {
                "incident_id": state.incident_id,
                "incident_data": incident_data,
                "severity_input": severity_input,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ASSESS,
            user_prompt=f"Incident assessment context:\n{assess_context}",
            schema=AssessmentOutput,
        )
        if hasattr(llm_result, "incident_type"):
            incident_type = getattr(llm_result, "incident_type", incident_type)
            assessment_score = getattr(llm_result, "assessment_score", assessment_score)
        logger.info(
            "llm_enhanced",
            node="assess_incident",
            llm_severity=getattr(llm_result, "severity", "unknown"),
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="assess_incident")

    step = ResponseReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="assess_incident",
        input_summary=f"Incident {state.incident_id} severity={severity_input}",
        output_summary=f"Assessment score={assessment_score}, type={incident_type}",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="assessment_engine",
    )

    await toolkit.record_response_metric("assessment", assessment_score)

    return {
        "severity": severity_input,
        "assessment_score": assessment_score,
        "incident_type": incident_type,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_incident",
        "session_start": start,
    }


async def plan_containment(state: IncidentResponseState) -> dict[str, Any]:
    """Plan containment actions based on incident assessment."""
    start = datetime.now(UTC)

    actions: list[ContainmentAction] = []
    if state.assessment_score >= 70:
        actions.append(
            ContainmentAction(
                action_id="c-001",
                action_type="network_isolation",
                target=state.incident_data.get("affected_host", "unknown"),
                risk_level="medium",
                automated=state.severity != "critical",
            )
        )
    if state.incident_data.get("malware_detected"):
        actions.append(
            ContainmentAction(
                action_id="c-002",
                action_type="process_kill",
                target=state.incident_data.get("malware_process", "unknown"),
                risk_level="low",
                automated=True,
            )
        )

    step = ResponseReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="plan_containment",
        input_summary=f"Severity={state.severity}, score={state.assessment_score}",
        output_summary=f"Planned {len(actions)} containment actions",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="containment_planner",
    )

    return {
        "containment_actions": actions,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "plan_containment",
    }


async def execute_containment(state: IncidentResponseState) -> dict[str, Any]:
    """Execute containment actions with OPA phase gate check.

    Evaluates the 'contain' phase gate before executing. Then runs
    CrowdStrike network isolation, AWS SG isolation, and K8s quarantine
    as appropriate based on the containment action types.
    """
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    # --- Phase gate: contain ---
    gate_result = await toolkit.evaluate_phase_gate(
        phase="contain",
        incident_id=state.incident_id,
        severity=state.severity,
        target_resources=[a.target for a in state.containment_actions],
    )
    phase_gates = dict(state.phase_gate_results)
    phase_gates["contain"] = gate_result

    if not gate_result.get("allowed", True):
        step = ResponseReasoningStep(
            step_number=len(state.reasoning_chain) + 1,
            action="execute_containment",
            input_summary="Containment phase gate denied",
            output_summary=f"Blocked: {gate_result.get('reason', 'policy denied')}",
            duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
            tool_used="policy_engine",
        )
        return {
            "containment_complete": False,
            "phase_gate_results": phase_gates,
            "reasoning_chain": [*state.reasoning_chain, step],
            "current_step": "execute_containment",
        }

    updated_actions: list[ContainmentAction] = []
    for action in state.containment_actions:
        if action.automated:
            if action.action_type == "network_isolation":
                # CrowdStrike host containment
                result = await toolkit.execute_containment(action.action_type, action.target)
                action.status = result.get("status", "failed")
                action.result = result
            elif action.action_type == "aws_sg_isolation":
                result = await toolkit.isolate_aws_security_group(
                    instance_id=action.target,
                    vpc_id=state.incident_data.get("vpc_id", ""),
                )
                action.status = result.get("status", "failed")
                action.result = result
            elif action.action_type == "k8s_quarantine":
                ns = state.incident_data.get("namespace", "default")
                result = await toolkit.quarantine_k8s_pod(namespace=ns, pod_name=action.target)
                action.status = result.get("status", "failed")
                action.result = result
            else:
                result = await toolkit.execute_containment(action.action_type, action.target)
                action.status = result.get("status", "failed")
                action.result = result
        updated_actions.append(action)

    all_complete = all(a.status == "completed" for a in updated_actions if a.automated)

    step = ResponseReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="execute_containment",
        input_summary=f"Executing {len(updated_actions)} containment actions",
        output_summary=f"Containment complete={all_complete}",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="containment_executor",
    )

    return {
        "containment_actions": updated_actions,
        "containment_complete": all_complete,
        "phase_gate_results": phase_gates,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "execute_containment",
    }


async def plan_eradication(state: IncidentResponseState) -> dict[str, Any]:
    """Plan and execute eradication steps with OPA phase gate."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    # --- Phase gate: eradicate ---
    gate_result = await toolkit.evaluate_phase_gate(
        phase="eradicate",
        incident_id=state.incident_id,
        severity=state.severity,
        target_resources=[state.incident_data.get("affected_host", "unknown")],
    )
    phase_gates = dict(state.phase_gate_results)
    phase_gates["eradicate"] = gate_result

    if not gate_result.get("allowed", True):
        step = ResponseReasoningStep(
            step_number=len(state.reasoning_chain) + 1,
            action="plan_eradication",
            input_summary="Eradication phase gate denied",
            output_summary=f"Blocked: {gate_result.get('reason', 'policy denied')}",
            duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
            tool_used="policy_engine",
        )
        return {
            "eradication_complete": False,
            "phase_gate_results": phase_gates,
            "reasoning_chain": [*state.reasoning_chain, step],
            "current_step": "plan_eradication",
        }

    raw_steps = await toolkit.plan_eradication(state.incident_type)
    steps = [EradicationStep(**s) for s in raw_steps if isinstance(s, dict)]

    if not steps and state.incident_type:
        steps.append(
            EradicationStep(
                step_id="e-001",
                step_type="malware_removal",
                target=state.incident_data.get("affected_host", "unknown"),
                description=f"Remove {state.incident_type} artifacts",
            )
        )

    # Execute each eradication step
    for erad_step in steps:
        erad_result = await toolkit.execute_eradication(
            step_type=erad_step.step_type,
            target=erad_step.target or state.incident_data.get("affected_host", "unknown"),
            incident_type=state.incident_type,
        )
        erad_step.status = erad_result.get("status", "completed")

    step = ResponseReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="plan_eradication",
        input_summary=f"Planning eradication for {state.incident_type}",
        output_summary=f"Planned and executed {len(steps)} eradication steps",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="eradication_planner",
    )

    return {
        "eradication_steps": steps,
        "eradication_complete": True,
        "phase_gate_results": phase_gates,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "plan_eradication",
    }


async def plan_recovery(state: IncidentResponseState) -> dict[str, Any]:
    """Plan recovery tasks with OPA phase gate."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    # --- Phase gate: recover ---
    gate_result = await toolkit.evaluate_phase_gate(
        phase="recover",
        incident_id=state.incident_id,
        severity=state.severity,
    )
    phase_gates = dict(state.phase_gate_results)
    phase_gates["recover"] = gate_result

    if not gate_result.get("allowed", True):
        step = ResponseReasoningStep(
            step_number=len(state.reasoning_chain) + 1,
            action="plan_recovery",
            input_summary="Recovery phase gate denied",
            output_summary=f"Blocked: {gate_result.get('reason', 'policy denied')}",
            duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
            tool_used="policy_engine",
        )
        return {
            "recovery_complete": False,
            "phase_gate_results": phase_gates,
            "reasoning_chain": [*state.reasoning_chain, step],
            "current_step": "plan_recovery",
        }

    tasks: list[RecoveryTask] = []
    affected_services = state.incident_data.get("affected_services", [])
    for svc in affected_services:
        tasks.append(
            RecoveryTask(
                task_id=f"r-{len(tasks) + 1:03d}",
                task_type="service_restart",
                service=svc,
                priority="high" if state.severity in ("critical", "high") else "medium",
                estimated_duration_min=15,
            )
        )

    if not tasks:
        tasks.append(
            RecoveryTask(
                task_id="r-001",
                task_type="health_check",
                service="all",
                priority="medium",
                estimated_duration_min=5,
            )
        )

    # Execute recovery actions
    for task in tasks:
        restore_result = await toolkit.execute_restore(
            service=task.service,
            task_type=task.task_type,
        )
        task.status = restore_result.get("status", "completed")

    step = ResponseReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="plan_recovery",
        input_summary=f"Planning recovery for {len(affected_services)} services",
        output_summary=f"Planned {len(tasks)} recovery tasks",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="recovery_planner",
    )

    return {
        "recovery_tasks": tasks,
        "phase_gate_results": phase_gates,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "plan_recovery",
    }


async def validate_response(state: IncidentResponseState) -> dict[str, Any]:
    """Validate that incident response is complete."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    validation = await toolkit.validate_recovery(state.incident_id)
    passed = validation.get("passed", False)

    step = ResponseReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="validate_response",
        input_summary=f"Validating response for incident {state.incident_id}",
        output_summary=f"Validation passed={passed}",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="validation_engine",
    )

    return {
        "validation_passed": passed,
        "validation_results": validation,
        "recovery_complete": True,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "validate_response",
    }


async def notify_stakeholders(state: IncidentResponseState) -> dict[str, Any]:
    """Send notifications via PagerDuty, Slack, and create ServiceNow ticket."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    notification_result = await toolkit.notify_stakeholders(state.incident_data)

    # Also create ServiceNow ticket
    snow_result = await toolkit.create_servicenow_ticket(
        {
            "incident_id": state.incident_id,
            "severity": state.severity,
            "type": state.incident_type,
        }
    )
    notification_result["servicenow"] = snow_result

    step = ResponseReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="notify_stakeholders",
        input_summary=f"Notifying for incident {state.incident_id}",
        output_summary=f"Notifications: {notification_result.get('notification_status')}",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="notification_engine",
    )

    return {
        "notification_results": notification_result,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "notify_stakeholders",
    }


async def build_timeline(state: IncidentResponseState) -> dict[str, Any]:
    """Build post-incident timeline from multi-source data with LLM summarization."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    # Build multi-source timeline
    raw_timeline = await toolkit.build_investigation_timeline(
        {
            "incident_id": state.incident_id,
            "affected_host": state.incident_data.get("affected_host", "*"),
            "timeframe": state.incident_data.get("timeframe", "-24h"),
        }
    )

    # LLM enhancement: summarize the timeline
    try:
        import json as _json

        timeline_context = _json.dumps(
            {
                "incident_id": state.incident_id,
                "incident_type": state.incident_type,
                "severity": state.severity,
                "events": raw_timeline.get("events", [])[:50],  # Limit for context window
                "sources": raw_timeline.get("sources_queried", []),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_TIMELINE,
            user_prompt=f"Incident timeline:\n{timeline_context}",
            schema=TimelineSummaryOutput,
        )
        if hasattr(llm_result, "summary"):
            raw_timeline["summary"] = getattr(llm_result, "summary", "")
            raw_timeline["attack_chain"] = getattr(llm_result, "attack_chain", [])
            raw_timeline["key_findings"] = getattr(llm_result, "key_findings", [])
            raw_timeline["recommended_actions"] = getattr(llm_result, "recommended_actions", [])
        logger.info("llm_enhanced", node="build_timeline")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="build_timeline")
        # Heuristic fallback: chronological event list as summary
        events = raw_timeline.get("events", [])
        raw_timeline["summary"] = (
            f"Incident {state.incident_id} ({state.incident_type}): "
            f"{len(events)} events across {', '.join(raw_timeline.get('sources_queried', []))}."
        )
        raw_timeline["attack_chain"] = []
        raw_timeline["key_findings"] = [
            f"Total events: {len(events)}",
            f"Sources: {', '.join(raw_timeline.get('sources_queried', []))}",
        ]
        raw_timeline["recommended_actions"] = [
            "Review timeline for gaps in visibility",
            "Validate all IOCs have been eradicated",
        ]

    step = ResponseReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="build_timeline",
        input_summary=f"Building timeline for {state.incident_id}",
        output_summary=f"Timeline: {raw_timeline.get('event_count', 0)} events",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="timeline_builder",
    )

    return {
        "timeline": raw_timeline,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "build_timeline",
    }


async def finalize_response(state: IncidentResponseState) -> dict[str, Any]:
    """Finalize incident response and record metrics."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    await toolkit.record_response_metric("response_duration_ms", float(duration_ms))

    step = ResponseReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="finalize_response",
        input_summary=f"Finalizing response for incident {state.incident_id}",
        output_summary=f"Response complete in {duration_ms}ms",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used=None,
    )

    return {
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
