"""Agent Governance Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog

from shieldops.utils.llm import llm_structured

from .models import (
    AgentCapability,
    BoundaryViolation,
    GovernanceStage,
)
from .prompts import (
    SYSTEM_ASSESS,
    SYSTEM_REPORT,
    CapabilityAssessmentResult,
    GovernanceReportResult,
)
from .tools import AgentGovernanceToolkit

logger = structlog.get_logger()


async def discover_agents(state: dict[str, Any], toolkit: AgentGovernanceToolkit) -> dict[str, Any]:
    """Discover all AI agents in the tenant."""
    logger.info("agent_governance.node.discover")

    tenant_id = state.get("tenant_id", "")
    agents = await toolkit.discover_agents(tenant_id)

    return {
        "stage": GovernanceStage.ASSESS_CAPABILITIES.value,
        "discovered_agents": agents,
        "total_agents": len(agents),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Discovered {len(agents)} AI agents in tenant {tenant_id}"],
    }


async def assess_capabilities(
    state: dict[str, Any], toolkit: AgentGovernanceToolkit
) -> dict[str, Any]:
    """Assess agent capabilities against governance policies."""
    logger.info("agent_governance.node.assess")

    agents = state.get("discovered_agents", [])
    capabilities, unauthorized = await toolkit.assess_capabilities(agents)
    caps_data = [c.model_dump(mode="json") for c in capabilities]

    reasoning_note = (
        f"Assessed {len(capabilities)} capabilities across {len(agents)} agents, "
        f"{unauthorized} unauthorized"
    )

    if capabilities:
        try:
            context = json.dumps(
                {
                    "agents": len(agents),
                    "capabilities": [
                        {
                            "agent": c.agent_id,
                            "capability": c.capability_name,
                            "risk": c.risk_level,
                            "approved": c.approved,
                        }
                        for c in capabilities[:15]
                    ],
                },
                default=str,
            )
            result = cast(
                CapabilityAssessmentResult,
                await llm_structured(
                    system_prompt=SYSTEM_ASSESS,
                    user_prompt=f"Agent capabilities:\n{context}",
                    schema=CapabilityAssessmentResult,
                ),
            )
            reasoning_note = f"{result.summary}. {reasoning_note}"
        except Exception:
            logger.debug("llm_fallback", agent="agent_governance", node="assess")

    return {
        "stage": GovernanceStage.ENFORCE_BOUNDARIES.value,
        "capabilities": caps_data,
        "unauthorized_capabilities": unauthorized,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def enforce_boundaries(
    state: dict[str, Any], toolkit: AgentGovernanceToolkit
) -> dict[str, Any]:
    """Enforce capability boundaries."""
    logger.info("agent_governance.node.enforce")

    raw_caps = state.get("capabilities", [])
    capabilities = [AgentCapability(**c) for c in raw_caps]
    violations = await toolkit.enforce_boundaries(capabilities)
    violations_data = [v.model_dump(mode="json") for v in violations]

    return {
        "stage": GovernanceStage.EVALUATE_ESCALATIONS.value,
        "violations": violations_data,
        "enforcements_applied": len(violations),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Enforced boundaries: {len(violations)} violations detected"],
    }


async def evaluate_escalations(
    state: dict[str, Any], toolkit: AgentGovernanceToolkit
) -> dict[str, Any]:
    """Evaluate and create escalation records."""
    logger.info("agent_governance.node.escalate")

    raw_violations = state.get("violations", [])
    violations = [BoundaryViolation(**v) for v in raw_violations]
    escalations = await toolkit.evaluate_escalations(violations)
    escalations_data = [e.model_dump(mode="json") for e in escalations]

    return {
        "stage": GovernanceStage.AUDIT_COMPLIANCE.value,
        "escalations": escalations_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Created {len(escalations)} escalation records"],
    }


async def audit_compliance(
    state: dict[str, Any], toolkit: AgentGovernanceToolkit
) -> dict[str, Any]:
    """Audit overall compliance posture."""
    logger.info("agent_governance.node.audit")

    agents = state.get("discovered_agents", [])
    raw_caps = state.get("capabilities", [])
    raw_violations = state.get("violations", [])
    capabilities = [AgentCapability(**c) for c in raw_caps]
    violations = [BoundaryViolation(**v) for v in raw_violations]

    score, policy_violations = await toolkit.audit_compliance(agents, capabilities, violations)

    return {
        "stage": GovernanceStage.REPORT.value,
        "compliance_score": score,
        "policy_violations": policy_violations,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Compliance score: {score}%, {policy_violations} policy violations"],
    }


async def generate_report(state: dict[str, Any], toolkit: AgentGovernanceToolkit) -> dict[str, Any]:
    """Generate governance report."""
    logger.info("agent_governance.node.report")

    total_agents = state.get("total_agents", 0)
    unauthorized = state.get("unauthorized_capabilities", 0)
    enforcements = state.get("enforcements_applied", 0)
    score = state.get("compliance_score", 0.0)
    policy_violations = state.get("policy_violations", 0)

    summary = (
        f"Governed {total_agents} AI agents: {unauthorized} unauthorized capabilities, "
        f"{enforcements} enforcements, compliance={score}%, "
        f"{policy_violations} policy violations"
    )

    try:
        context = json.dumps(
            {
                "total_agents": total_agents,
                "unauthorized_capabilities": unauthorized,
                "enforcements_applied": enforcements,
                "compliance_score": score,
                "policy_violations": policy_violations,
                "escalations": len(state.get("escalations", [])),
            },
            default=str,
        )
        result = cast(
            GovernanceReportResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Governance report context:\n{context}",
                schema=GovernanceReportResult,
            ),
        )
        summary = result.executive_summary
    except Exception:
        logger.debug("llm_fallback", agent="agent_governance", node="report")

    return {
        "stage": GovernanceStage.REPORT.value,
        "summary": summary,
        "reasoning_chain": state.get("reasoning_chain", []) + [summary],
    }
