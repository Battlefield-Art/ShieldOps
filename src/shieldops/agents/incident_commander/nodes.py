"""Node implementations for the Incident Commander Agent LangGraph workflow.

Each node is an async function that:
1. Queries external systems via the IncidentCommanderToolkit
2. Coordinates sub-agents for investigation, remediation, and security
3. Updates the incident commander state with findings and decisions
4. Records its reasoning step in the audit trail
"""

from datetime import UTC, datetime
from typing import Any, cast

import structlog
from pydantic import BaseModel, Field

from shieldops.agents.incident_commander.models import (
    CommandDecision,
    CommandStage,
    EscalationStatus,
    IncidentCommanderState,
    IncidentContext,
    ReasoningStep,
    SeverityLevel,
)
from shieldops.agents.incident_commander.prompts import SYSTEM_MONITOR, MonitoringResult
from shieldops.agents.incident_commander.tools import IncidentCommanderToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

# Module-level toolkit reference, set by the runner at graph construction time.
_toolkit: IncidentCommanderToolkit | None = None


def set_toolkit(toolkit: IncidentCommanderToolkit) -> None:
    """Configure the toolkit used by all nodes. Called once at startup."""
    global _toolkit
    _toolkit = toolkit


class _LLMTriageAssessment(BaseModel):
    """LLM-generated incident triage assessment."""

    confirmed_severity: str = Field(description="Confirmed severity level (sev1, sev2, sev3, sev4)")
    blast_radius_assessment: str = Field(
        description="Assessment of the incident blast radius and impact"
    )
    recommended_agents: list[str] = Field(
        description="Agents to dispatch (investigation, remediation, security)"
    )
    requires_approval: bool = Field(
        description="Whether human approval is needed before remediation"
    )
    confidence: float = Field(description="Triage confidence (0.0-1.0)", ge=0.0, le=1.0)
    reasoning: str = Field(description="Explanation of the triage decision")


def _get_toolkit() -> IncidentCommanderToolkit:
    if _toolkit is None:
        return IncidentCommanderToolkit()  # Empty toolkit -- safe for tests
    return _toolkit


async def triage(state: IncidentCommanderState) -> dict[str, Any]:
    """Classify incident severity, identify blast radius, and plan response.

    Performs initial triage of the incident to determine severity,
    affected services, and which agents need to be dispatched.
    """
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    context = state.incident_context or IncidentContext(
        alert_id="unknown",
        service="unknown",
    )

    logger.info(
        "incident_commander_triaging",
        request_id=state.request_id,
        alert_id=context.alert_id,
        service=context.service,
    )

    triage_result = await toolkit.triage_incident(context)

    blast_radius = triage_result.get("blast_radius", [context.service])
    confirmed_severity = triage_result.get("confirmed_severity", context.severity.value)
    recommended_agents = triage_result.get("recommended_agents", ["investigation"])
    triage_confidence = 0.8 if confirmed_severity in ("sev1", "sev2") else 0.6
    requires_approval = confirmed_severity == "sev1"
    llm_reasoning = ""

    # --- LLM enhancement: improve severity classification ---
    try:
        assessment = await llm_structured(
            system_prompt=(
                "You are an incident commander for a large-scale SRE platform. "
                "Analyze the incoming incident and classify its severity accurately. "
                "Consider blast radius, service criticality, environment, and "
                "potential customer impact. Be conservative — prefer higher severity "
                "when uncertain."
            ),
            user_prompt=(
                f"Alert ID: {context.alert_id}\n"
                f"Service: {context.service}\n"
                f"Environment: {context.environment}\n"
                f"Initial severity: {context.severity.value}\n"
                f"Description: {context.description}\n"
                f"Tags: {context.tags}\n"
                f"Affected services: {context.affected_services}\n\n"
                f"Toolkit triage result:\n"
                f"  Blast radius: {blast_radius}\n"
                f"  Confirmed severity: {confirmed_severity}\n"
                f"  Recommended agents: {recommended_agents}"
            ),
            schema=_LLMTriageAssessment,
        )
        if isinstance(assessment, _LLMTriageAssessment):
            # LLM can upgrade severity but not downgrade
            severity_order = ["sev4", "sev3", "sev2", "sev1"]
            llm_sev = assessment.confirmed_severity
            if llm_sev in severity_order and severity_order.index(llm_sev) > severity_order.index(
                confirmed_severity
            ):
                confirmed_severity = llm_sev
            # LLM can require approval but not remove it
            if assessment.requires_approval:
                requires_approval = True
            # Use LLM confidence if higher
            if assessment.confidence > triage_confidence:
                triage_confidence = assessment.confidence
            # Merge recommended agents
            for agent in assessment.recommended_agents:
                if agent not in recommended_agents:
                    recommended_agents.append(agent)
            llm_reasoning = assessment.reasoning
            logger.info(
                "llm_enhanced",
                agent="incident_commander",
                node="triage",
                llm_severity=llm_sev,
                llm_confidence=assessment.confidence,
            )
    except Exception:
        logger.debug("llm_fallback", agent="incident_commander", node="triage")

    # Build triage decision
    triage_reasoning = (
        f"Incident {context.alert_id} triaged as {confirmed_severity}. "
        f"Blast radius: {len(blast_radius)} services. "
        f"Dispatching: {', '.join(recommended_agents)}."
    )
    if llm_reasoning:
        triage_reasoning += f" LLM: {llm_reasoning[:150]}"

    decision = CommandDecision(
        action="triage_complete",
        reasoning=triage_reasoning,
        confidence=triage_confidence,
        requires_approval=requires_approval,
    )

    output_summary = (
        f"Triaged incident {context.alert_id} as {confirmed_severity}. "
        f"Blast radius: {blast_radius}. "
        f"Recommended agents: {recommended_agents}."
    )

    step = ReasoningStep(
        step_number=1,
        action="triage",
        input_summary=f"Alert: {context.alert_id}, Service: {context.service}",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="triage_incident",
    )

    return {
        "stage": CommandStage.COORDINATE,
        "blast_radius": blast_radius,
        "decisions": [decision],
        "confidence_score": decision.confidence,
        "session_start": start,
        "reasoning_chain": [step],
        "current_step": "triage",
    }


async def coordinate_agents(state: IncidentCommanderState) -> dict[str, Any]:
    """Dispatch appropriate sub-agents based on triage results.

    Creates tasks for investigation, remediation, and security agents
    depending on the incident severity and blast radius.
    """
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    context = state.incident_context or IncidentContext(
        alert_id="unknown",
        service="unknown",
    )

    logger.info(
        "incident_commander_coordinating",
        request_id=state.request_id,
        blast_radius=len(state.blast_radius),
    )

    # Determine which agents to dispatch based on severity
    severity = context.severity
    tasks = list(state.agent_tasks)  # preserve existing tasks

    # Always dispatch investigation
    inv_task = await toolkit.dispatch_agent(
        agent_type="investigation",
        task=f"Investigate incident {context.alert_id} affecting {context.service}",
    )
    tasks.append(inv_task)

    # Dispatch remediation for sev1/sev2
    if severity in (SeverityLevel.SEV1, SeverityLevel.SEV2):
        rem_task = await toolkit.dispatch_agent(
            agent_type="remediation",
            task=(f"Prepare remediation for {context.service} in {context.environment}"),
        )
        tasks.append(rem_task)

    # Dispatch security for production
    if context.environment == "production":
        sec_task = await toolkit.dispatch_agent(
            agent_type="security",
            task=f"Security assessment for incident {context.alert_id}",
        )
        tasks.append(sec_task)

    new_tasks_count = len(tasks) - len(state.agent_tasks)
    output_summary = f"Dispatched {new_tasks_count} agent tasks. Total active tasks: {len(tasks)}."

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="coordinate_agents",
        input_summary=(
            f"Severity: {severity.value}, "
            f"Environment: {context.environment}, "
            f"Blast radius: {len(state.blast_radius)} services"
        ),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="dispatch_agent",
    )

    return {
        "agent_tasks": tasks,
        "stage": CommandStage.RESOLVE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "coordinate_agents",
    }


async def monitor_and_decide(state: IncidentCommanderState) -> dict[str, Any]:
    """Monitor agent progress and make resolution or escalation decisions.

    Checks the status of dispatched agents, evaluates whether the
    incident can be resolved or needs escalation, and records decisions.
    """
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    context = state.incident_context or IncidentContext(
        alert_id="unknown",
        service="unknown",
    )

    logger.info(
        "incident_commander_monitoring",
        request_id=state.request_id,
        active_tasks=len(state.agent_tasks),
    )

    # Check status of all dispatched tasks
    updated_tasks = []
    all_completed = True
    findings: list[str] = []

    for task in state.agent_tasks:
        if task.status in ("completed", "failed"):
            updated_tasks.append(task)
            continue

        status = await toolkit.check_agent_status(task.task_id)
        task_copy = task.model_copy(
            update={
                "status": status.get("status", task.status),
                "result": status,
            }
        )
        updated_tasks.append(task_copy)

        if task_copy.status != "completed":
            all_completed = False
        else:
            findings.extend(status.get("findings", []))

    # Decide: resolve, escalate, or continue
    decisions = list(state.decisions)
    escalation = state.escalation_status
    confidence = state.confidence_score
    llm_decision_used = False

    # LLM enhancement: richer decision reasoning
    try:
        import json

        task_status_summary = json.dumps(
            [
                {
                    "agent_type": t.agent_type,
                    "status": t.status,
                    "task": t.task_description,
                }
                for t in updated_tasks
            ],
            default=str,
        )
        user_prompt = (
            f"Incident: {context.alert_id}, Service: {context.service}, "
            f"Severity: {context.severity.value}\n"
            f"Blast radius: {state.blast_radius}\n"
            f"Agent tasks:\n{task_status_summary}\n"
            f"Findings so far: {findings[:5]}\n"
            f"All completed: {all_completed}"
        )
        llm_result = cast(
            MonitoringResult,
            await llm_structured(
                system_prompt=SYSTEM_MONITOR,
                user_prompt=user_prompt,
                schema=MonitoringResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            node="monitor_and_decide",
            llm_decision=llm_result.decision,
            llm_confidence=llm_result.confidence,
        )
        # Use LLM decision if confidence is reasonable
        if llm_result.confidence >= 0.5:
            llm_decision_used = True
            confidence = llm_result.confidence
            decisions.append(
                CommandDecision(
                    action=llm_result.decision,
                    reasoning=llm_result.reasoning,
                    confidence=llm_result.confidence,
                    requires_approval=llm_result.decision == "escalate",
                )
            )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="monitor_and_decide")

    if not llm_decision_used:
        if all_completed:
            # All agents done: decide to resolve
            confidence = 0.9
            decisions.append(
                CommandDecision(
                    action="resolve",
                    reasoning=(
                        f"All {len(updated_tasks)} agent tasks completed. "
                        f"Findings: {findings[:3]}. Proceeding to resolution."
                    ),
                    confidence=confidence,
                    requires_approval=False,
                )
            )
        elif context.severity == SeverityLevel.SEV1:
            # SEV1 not yet resolved: escalate
            escalation = EscalationStatus.VP_ENG
            escalation_result = await toolkit.escalate(
                level=escalation,
                reason=(
                    f"SEV1 incident {context.alert_id} — "
                    f"{len(updated_tasks)} tasks still in progress"
                ),
            )
            decisions.append(
                CommandDecision(
                    action="escalate",
                    reasoning=(
                        f"SEV1 incident not yet resolved. "
                        f"Escalated to {escalation.value}. "
                        f"Result: {escalation_result.get('status')}"
                    ),
                    confidence=0.7,
                    requires_approval=True,
                )
            )
        else:
            # Still in progress for lower severity
            decisions.append(
                CommandDecision(
                    action="continue_monitoring",
                    reasoning=(
                        f"Waiting for {sum(1 for t in updated_tasks if t.status != 'completed')} "
                        f"tasks to complete."
                    ),
                    confidence=0.5,
                    requires_approval=False,
                )
            )

    output_summary = (
        f"Checked {len(updated_tasks)} tasks. "
        f"All completed: {all_completed}. "
        f"Decision: {decisions[-1].action}."
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="monitor_and_decide",
        input_summary=f"Monitoring {len(state.agent_tasks)} active tasks",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="check_agent_status",
    )

    return {
        "agent_tasks": updated_tasks,
        "decisions": decisions,
        "escalation_status": escalation,
        "confidence_score": confidence,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "monitor_and_decide",
    }


async def close_incident(state: IncidentCommanderState) -> dict[str, Any]:
    """Generate resolution summary, close the incident, and update runbooks.

    Compiles findings from all agent tasks into a comprehensive
    resolution summary and marks the incident as resolved.
    """
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    context = state.incident_context or IncidentContext(
        alert_id="unknown",
        service="unknown",
    )

    logger.info(
        "incident_commander_closing",
        request_id=state.request_id,
        alert_id=context.alert_id,
    )

    # Compile resolution summary from all tasks
    task_summaries = []
    for task in state.agent_tasks:
        task_summaries.append(f"[{task.agent_type}] {task.task_description} -> {task.status}")

    decision_summaries = []
    for d in state.decisions:
        decision_summaries.append(f"{d.action}: {d.reasoning}")

    summary = (
        f"Incident {context.alert_id} resolved.\n"
        f"Service: {context.service} ({context.environment})\n"
        f"Severity: {context.severity.value}\n"
        f"Blast radius: {state.blast_radius}\n"
        f"Tasks completed: {len(state.agent_tasks)}\n"
        f"Task details:\n" + "\n".join(f"  - {s}" for s in task_summaries)
    )

    resolve_result = await toolkit.resolve_incident(summary)

    # Calculate session duration
    session_duration_ms = 0
    if state.session_start:
        session_duration_ms = _elapsed_ms(state.session_start)

    output_summary = (
        f"Incident {context.alert_id} closed. "
        f"Resolution status: {resolve_result.get('status')}. "
        f"Total duration: {session_duration_ms}ms."
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="close_incident",
        input_summary=(
            f"Closing incident {context.alert_id} with {len(state.agent_tasks)} completed tasks"
        ),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="resolve_incident",
    )

    return {
        "resolution_summary": summary,
        "stage": CommandStage.REVIEW,
        "session_duration_ms": session_duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }


# --- Private helpers ---


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)
