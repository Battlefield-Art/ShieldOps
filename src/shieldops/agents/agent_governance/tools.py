"""Agent Governance Agent — Tool functions for AI agent governance."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

import structlog

from .models import (
    AgentCapability,
    BoundaryViolation,
    EnforcementAction,
    EscalationRecord,
    RiskLevel,
)

logger = structlog.get_logger()

# Capability boundary definitions
_CAPABILITY_BOUNDARIES: dict[str, dict[str, Any]] = {
    "data_access": {
        "max_scope": "read_only",
        "requires_approval": True,
        "risk_level": "high",
        "allowed_actions": ["read", "list", "query"],
    },
    "infrastructure_modify": {
        "max_scope": "non_production",
        "requires_approval": True,
        "risk_level": "critical",
        "allowed_actions": ["scale", "restart", "update_config"],
    },
    "external_api": {
        "max_scope": "rate_limited",
        "requires_approval": False,
        "risk_level": "medium",
        "allowed_actions": ["get", "post_limited"],
    },
    "credential_access": {
        "max_scope": "short_lived",
        "requires_approval": True,
        "risk_level": "critical",
        "allowed_actions": ["read_secret", "rotate"],
    },
    "llm_invocation": {
        "max_scope": "cost_capped",
        "requires_approval": False,
        "risk_level": "medium",
        "allowed_actions": ["invoke", "stream"],
    },
}

_ESCALATION_CHAINS: dict[str, list[str]] = {
    "critical": ["soc_lead", "ciso", "incident_commander"],
    "high": ["soc_analyst", "soc_lead"],
    "medium": ["team_lead"],
    "low": ["auto_resolve"],
}


def _generate_id(prefix: str, *parts: str) -> str:
    raw = f"{':'.join(parts)}:{datetime.now(UTC).isoformat()}"
    return f"{prefix}-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


class AgentGovernanceToolkit:
    """Tools for AI agent governance and policy enforcement."""

    def __init__(
        self,
        registry_client: Any | None = None,
        policy_client: Any | None = None,
        notification_client: Any | None = None,
    ) -> None:
        self._registry = registry_client
        self._policy = policy_client
        self._notification = notification_client

    async def discover_agents(self, tenant_id: str) -> list[dict[str, Any]]:
        """Discover all AI agents in the tenant."""
        logger.info("agent_governance.discover", tenant_id=tenant_id)

        if self._registry:
            try:
                return await self._registry.list_agents(tenant_id=tenant_id)
            except Exception:
                logger.exception("agent_governance.discover.error")

        # Simulated discovery
        return [
            {
                "agent_id": "agent-001",
                "name": "data-processor",
                "framework": "langchain",
                "capabilities": ["data_access", "llm_invocation"],
                "status": "active",
            },
            {
                "agent_id": "agent-002",
                "name": "infra-manager",
                "framework": "crewai",
                "capabilities": ["infrastructure_modify", "credential_access"],
                "status": "active",
            },
            {
                "agent_id": "agent-003",
                "name": "report-generator",
                "framework": "llamaindex",
                "capabilities": ["llm_invocation", "external_api"],
                "status": "active",
            },
            {
                "agent_id": "agent-004",
                "name": "unregistered-bot",
                "framework": "custom",
                "capabilities": ["data_access", "credential_access", "infrastructure_modify"],
                "status": "active",
            },
        ]

    async def assess_capabilities(
        self, agents: list[dict[str, Any]]
    ) -> tuple[list[AgentCapability], int]:
        """Assess capabilities against governance boundaries."""
        logger.info("agent_governance.assess", agent_count=len(agents))

        capabilities: list[AgentCapability] = []
        unauthorized = 0

        for agent in agents:
            for cap_name in agent.get("capabilities", []):
                boundary = _CAPABILITY_BOUNDARIES.get(cap_name, {})
                risk = RiskLevel(boundary.get("risk_level", "medium"))
                requires_approval = boundary.get("requires_approval", True)

                approved = not requires_approval
                if not approved:
                    unauthorized += 1

                capabilities.append(
                    AgentCapability(
                        id=_generate_id("CAP", agent["agent_id"], cap_name),
                        agent_id=agent["agent_id"],
                        capability_name=cap_name,
                        scope=boundary.get("max_scope", "unknown"),
                        risk_level=risk,
                        approved=approved,
                    )
                )

        return capabilities, unauthorized

    async def enforce_boundaries(
        self, capabilities: list[AgentCapability]
    ) -> list[BoundaryViolation]:
        """Enforce capability boundaries and detect violations."""
        logger.info("agent_governance.enforce", capability_count=len(capabilities))

        violations: list[BoundaryViolation] = []
        now = datetime.now(UTC)

        for cap in capabilities:
            if not cap.approved and cap.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                action = (
                    EnforcementAction.BLOCK
                    if cap.risk_level == RiskLevel.CRITICAL
                    else EnforcementAction.RESTRICT
                )
                violations.append(
                    BoundaryViolation(
                        id=_generate_id("VIO", cap.agent_id, cap.capability_name),
                        agent_id=cap.agent_id,
                        violation_type="unauthorized_capability",
                        capability_attempted=cap.capability_name,
                        action_taken=action,
                        severity=cap.risk_level,
                        details=f"Agent {cap.agent_id} has unapproved {cap.capability_name} "
                        f"capability with {cap.risk_level} risk",
                        detected_at=now,
                    )
                )

        return violations

    async def evaluate_escalations(
        self, violations: list[BoundaryViolation]
    ) -> list[EscalationRecord]:
        """Evaluate violations and create escalation records."""
        logger.info("agent_governance.escalate", violation_count=len(violations))

        escalations: list[EscalationRecord] = []
        now = datetime.now(UTC)

        for violation in violations:
            chain = _ESCALATION_CHAINS.get(violation.severity.value, ["team_lead"])
            escalated_to = chain[0] if chain else "team_lead"

            escalations.append(
                EscalationRecord(
                    id=_generate_id("ESC", violation.agent_id, violation.violation_type),
                    agent_id=violation.agent_id,
                    reason=f"{violation.violation_type}: {violation.details}",
                    escalated_to=escalated_to,
                    created_at=now,
                )
            )

            if self._notification:
                try:
                    await self._notification.send(
                        recipient=escalated_to,
                        message=f"Governance violation: {violation.details}",
                    )
                except Exception:
                    logger.exception("agent_governance.notify.error")

        return escalations

    async def audit_compliance(
        self,
        agents: list[dict[str, Any]],
        capabilities: list[AgentCapability],
        violations: list[BoundaryViolation],
    ) -> tuple[float, int]:
        """Calculate compliance score and count policy violations."""
        logger.info("agent_governance.audit")

        total_checks = len(capabilities) if capabilities else 1
        approved_count = sum(1 for c in capabilities if c.approved)
        compliance_score = (approved_count / total_checks) * 100

        policy_violations = len(violations)

        # Check for unregistered agents
        for agent in agents:
            if agent.get("framework") == "custom" and not agent.get("registered", False):
                policy_violations += 1

        return round(compliance_score, 1), policy_violations
