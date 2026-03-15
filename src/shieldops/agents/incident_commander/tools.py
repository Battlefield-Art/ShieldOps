"""Tool functions for the Incident Commander Agent.

These bridge incident management systems, sub-agent dispatching, and
escalation channels to the agent's LangGraph nodes. Each tool is a
self-contained async function with real backend path + mock fallback.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.incident_commander.models import (
    AgentTask,
    EscalationStatus,
    IncidentContext,
    SeverityLevel,
)

logger = structlog.get_logger()


class IncidentCommanderToolkit:
    """Collection of tools available to the incident commander agent.

    Injected into nodes at graph construction time to decouple agent logic
    from specific backend implementations.
    """

    def __init__(
        self,
        incident_client: Any = None,
        agent_dispatcher: Any = None,
        escalation_client: Any = None,
        runbook_client: Any = None,
    ) -> None:
        self._incident_client = incident_client
        self._agent_dispatcher = agent_dispatcher
        self._escalation_client = escalation_client
        self._runbook_client = runbook_client

    async def triage_incident(
        self,
        context: IncidentContext,
    ) -> dict[str, Any]:
        """Classify incident severity and identify affected services.

        Queries the incident management system for additional context,
        identifies blast radius, and confirms or adjusts severity.

        Args:
            context: The initial incident context from the alert.

        Returns:
            Dictionary with triage results including severity, blast radius,
            and recommended response actions.
        """
        if self._incident_client is not None:
            try:
                triage_result = await self._incident_client.triage(
                    alert_id=context.alert_id,
                    service=context.service,
                    environment=context.environment,
                )
                logger.info(
                    "incident_triaged_via_backend",
                    alert_id=context.alert_id,
                    severity=triage_result.get("severity", context.severity),
                )
                return triage_result
            except Exception as e:
                logger.error(
                    "incident_triage_backend_failed",
                    alert_id=context.alert_id,
                    error=str(e),
                )

        # Mock fallback: derive triage from context
        affected = list(set([context.service, *context.affected_services]))
        severity = context.severity

        # Auto-escalate if multiple services affected
        if len(affected) > 3:
            severity = SeverityLevel.SEV1
        elif len(affected) > 1:
            severity = min(severity, SeverityLevel.SEV2, key=lambda s: s.value)

        result: dict[str, Any] = {
            "alert_id": context.alert_id,
            "confirmed_severity": severity.value,
            "blast_radius": affected,
            "environment": context.environment,
            "recommended_agents": self._recommend_agents(severity, context),
            "triaged_at": datetime.now(UTC).isoformat(),
        }

        logger.info(
            "incident_triaged",
            alert_id=context.alert_id,
            severity=severity.value,
            blast_radius=len(affected),
        )
        return result

    async def dispatch_agent(
        self,
        agent_type: str,
        task: str,
    ) -> AgentTask:
        """Dispatch a sub-agent to perform a specific task.

        Args:
            agent_type: Type of agent to dispatch (investigation/remediation/security).
            task: Description of the task for the agent.

        Returns:
            An AgentTask representing the dispatched work.
        """
        task_id = f"task-{uuid4().hex[:8]}"

        if self._agent_dispatcher is not None:
            try:
                result = await self._agent_dispatcher.dispatch(
                    agent_type=agent_type,
                    task_description=task,
                    task_id=task_id,
                )
                logger.info(
                    "agent_dispatched_via_backend",
                    agent_type=agent_type,
                    task_id=task_id,
                )
                return AgentTask(
                    task_id=task_id,
                    agent_type=agent_type,
                    task_description=task,
                    status=result.get("status", "dispatched"),
                    result=result,
                )
            except Exception as e:
                logger.error(
                    "agent_dispatch_backend_failed",
                    agent_type=agent_type,
                    error=str(e),
                )

        # Mock fallback
        logger.info(
            "agent_dispatched_mock",
            agent_type=agent_type,
            task_id=task_id,
        )
        return AgentTask(
            task_id=task_id,
            agent_type=agent_type,
            task_description=task,
            status="dispatched",
            result={"dispatched_at": datetime.now(UTC).isoformat()},
        )

    async def check_agent_status(
        self,
        task_id: str,
    ) -> dict[str, Any]:
        """Check completion status of a dispatched agent task.

        Args:
            task_id: The ID of the task to check.

        Returns:
            Dictionary with task status and any results.
        """
        if self._agent_dispatcher is not None:
            try:
                return await self._agent_dispatcher.check_status(task_id)
            except Exception as e:
                logger.error(
                    "agent_status_check_failed",
                    task_id=task_id,
                    error=str(e),
                )

        # Mock fallback: assume completed
        return {
            "task_id": task_id,
            "status": "completed",
            "completed_at": datetime.now(UTC).isoformat(),
            "findings": ["No anomalies detected"],
        }

    async def escalate(
        self,
        level: EscalationStatus,
        reason: str,
    ) -> dict[str, Any]:
        """Escalate incident to human decision makers.

        Args:
            level: The escalation level (team_lead, vp_eng, cto).
            reason: Justification for escalation.

        Returns:
            Dictionary with escalation result.
        """
        if self._escalation_client is not None:
            try:
                result = await self._escalation_client.escalate(
                    level=level.value,
                    reason=reason,
                )
                logger.info(
                    "incident_escalated_via_backend",
                    level=level.value,
                )
                return result
            except Exception as e:
                logger.error(
                    "escalation_backend_failed",
                    level=level.value,
                    error=str(e),
                )

        # Mock fallback
        logger.info(
            "incident_escalated",
            level=level.value,
            reason=reason,
        )
        return {
            "level": level.value,
            "reason": reason,
            "status": "escalated",
            "escalated_at": datetime.now(UTC).isoformat(),
            "notified": [f"{level.value}@company.com"],
        }

    async def resolve_incident(
        self,
        summary: str,
    ) -> dict[str, Any]:
        """Close the incident with a resolution summary.

        Args:
            summary: Description of the resolution and actions taken.

        Returns:
            Dictionary with resolution details.
        """
        if self._incident_client is not None:
            try:
                result = await self._incident_client.resolve(summary=summary)
                logger.info("incident_resolved_via_backend")
                return result
            except Exception as e:
                logger.error(
                    "incident_resolve_backend_failed",
                    error=str(e),
                )

        # Mock fallback
        logger.info("incident_resolved", summary_length=len(summary))
        return {
            "status": "resolved",
            "summary": summary,
            "resolved_at": datetime.now(UTC).isoformat(),
            "runbook_updated": False,
        }

    # --- Private helpers ---

    @staticmethod
    def _recommend_agents(
        severity: SeverityLevel,
        context: IncidentContext,
    ) -> list[str]:
        """Determine which sub-agents to dispatch based on severity and context."""
        agents = ["investigation"]

        if severity in (SeverityLevel.SEV1, SeverityLevel.SEV2):
            agents.append("remediation")

        # Always include security for production incidents
        if context.environment == "production":
            agents.append("security")

        return agents
