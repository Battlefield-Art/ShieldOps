"""Node implementations for the MCP Gateway Agent LangGraph workflow.

Each node is an async function that:
1. Calls tool functions to query servers, assess security, enforce policies
2. Uses the LLM (via ``llm_structured``) to analyze and reason about findings
3. Updates the gateway state with results
4. Records its reasoning step in the audit trail
"""

from __future__ import annotations

import time
from typing import Any, cast

import structlog

from shieldops.agents.mcp_gateway.models import (
    GatewayStage,
    MCPGatewayState,
    ReasoningStep,
)
from shieldops.agents.mcp_gateway.prompts import (
    SYSTEM_ABUSE_DETECTION,
    SYSTEM_POLICY_ENFORCEMENT,
    SYSTEM_SECURITY_ASSESSMENT,
    AbuseDetectionResult,
    PolicyRecommendationResult,
    SecurityAssessmentResult,
)
from shieldops.agents.mcp_gateway.tools import (
    assess_mcp_security,
    discover_mcp_servers,
    enforce_gateway_policies,
    monitor_mcp_traffic,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()


# -------------------------------------------------------------------
# Node: discover_servers
# -------------------------------------------------------------------


async def discover_servers(state: MCPGatewayState) -> dict[str, Any]:
    """Discover MCP servers registered for the tenant."""
    start = time.monotonic()
    logger.info(
        "mcp_gateway.node.discover_servers",
        request_id=state.request_id,
        tenant_id=state.tenant_id,
    )

    servers = await discover_mcp_servers(state.tenant_id)

    step = ReasoningStep(
        step=1,
        detail=f"Discovered {len(servers)} MCP servers for tenant {state.tenant_id}",
        confidence=0.95,
        metadata={"server_count": len(servers)},
    )

    return {
        "mcp_servers": servers,
        "stage": GatewayStage.ASSESS_SECURITY,
        "reasoning_chain": [step],
        "current_step": "discover_servers",
        "session_start": start,
    }


# -------------------------------------------------------------------
# Node: assess_security
# -------------------------------------------------------------------


async def assess_security(state: MCPGatewayState) -> dict[str, Any]:
    """Assess security posture of all discovered servers."""
    logger.info(
        "mcp_gateway.node.assess_security",
        request_id=state.request_id,
        server_count=len(state.mcp_servers),
    )

    assessments = await assess_mcp_security(state.mcp_servers)
    god_keys = sum(1 for a in assessments if a.god_key_detected)

    # LLM-powered assessment summary
    detail = f"Assessed {len(assessments)} servers, {god_keys} God Key patterns detected"
    if state.mcp_servers:
        context_lines = [
            "## MCP Server Security Assessment",
            f"Servers assessed: {len(state.mcp_servers)}",
            "",
        ]
        for srv in state.mcp_servers:
            context_lines.append(
                f"- {srv.server_name}: auth={srv.auth_method.value}, "
                f"tls={srv.tls_enabled}, rate_limit={srv.rate_limit_configured}"
            )
        for a in assessments:
            if a.vulnerabilities:
                context_lines.append(f"- Server {a.server_id}: {', '.join(a.vulnerabilities)}")

        try:
            result = cast(
                SecurityAssessmentResult,
                await llm_structured(
                    system_prompt=SYSTEM_SECURITY_ASSESSMENT,
                    user_prompt="\n".join(context_lines),
                    schema=SecurityAssessmentResult,
                ),
            )
            detail = result.summary
        except Exception as exc:
            logger.error("llm_security_assessment_failed", error=str(exc))
            detail += f" (LLM analysis failed: {exc})"

    step = ReasoningStep(
        step=len(state.reasoning_chain) + 1,
        detail=detail,
        confidence=0.90,
        metadata={"god_keys": god_keys, "assessments": len(assessments)},
    )

    return {
        "security_assessments": assessments,
        "god_keys_found": god_keys,
        "stage": GatewayStage.ENFORCE_POLICIES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_security",
    }


# -------------------------------------------------------------------
# Node: enforce_policies
# -------------------------------------------------------------------


async def enforce_policies(state: MCPGatewayState) -> dict[str, Any]:
    """Enforce gateway policies based on security assessments."""
    logger.info(
        "mcp_gateway.node.enforce_policies",
        request_id=state.request_id,
        assessment_count=len(state.security_assessments),
    )

    enforcements = await enforce_gateway_policies(state.security_assessments)

    # LLM-powered policy recommendations
    detail = f"Enforced {len(enforcements)} policies"
    if state.security_assessments:
        context_lines = [
            "## Security Assessment Results",
            f"Total assessments: {len(state.security_assessments)}",
            f"God Keys found: {state.god_keys_found}",
            "",
        ]
        for a in state.security_assessments:
            context_lines.append(
                f"- {a.server_id}: risk_score={a.risk_score}, "
                f"vulns={len(a.vulnerabilities)}, "
                f"god_key={a.god_key_detected}"
            )

        try:
            result = cast(
                PolicyRecommendationResult,
                await llm_structured(
                    system_prompt=SYSTEM_POLICY_ENFORCEMENT,
                    user_prompt="\n".join(context_lines),
                    schema=PolicyRecommendationResult,
                ),
            )
            n_pol = len(result.policies)
            reduction = result.estimated_risk_reduction
            detail = (
                f"Enforced {len(enforcements)} policies, "
                f"LLM recommended {n_pol} additional. "
                f"Estimated risk reduction: {reduction}"
            )
        except Exception as exc:
            logger.error("llm_policy_enforcement_failed", error=str(exc))
            detail += f" (LLM analysis failed: {exc})"

    step = ReasoningStep(
        step=len(state.reasoning_chain) + 1,
        detail=detail,
        confidence=0.85,
        metadata={"enforcements": len(enforcements)},
    )

    return {
        "policy_enforcements": enforcements,
        "stage": GatewayStage.MONITOR_TRAFFIC,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "enforce_policies",
    }


# -------------------------------------------------------------------
# Node: monitor_traffic
# -------------------------------------------------------------------


async def monitor_traffic(state: MCPGatewayState) -> dict[str, Any]:
    """Monitor gateway traffic for anomalies and abuse patterns."""
    logger.info(
        "mcp_gateway.node.monitor_traffic",
        request_id=state.request_id,
        server_count=len(state.mcp_servers),
    )

    anomalies = await monitor_mcp_traffic(state.mcp_servers)

    step = ReasoningStep(
        step=len(state.reasoning_chain) + 1,
        detail=f"Monitored traffic: {len(anomalies)} anomalies detected",
        confidence=0.88,
        metadata={
            "anomalies": len(anomalies),
            "blocked": sum(1 for a in anomalies if a.blocked),
        },
    )

    return {
        "traffic_anomalies": anomalies,
        "stage": GatewayStage.DETECT_ABUSE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "monitor_traffic",
    }


# -------------------------------------------------------------------
# Node: detect_abuse
# -------------------------------------------------------------------


async def detect_abuse(state: MCPGatewayState) -> dict[str, Any]:
    """Use LLM to analyze traffic anomalies and confirm abuse patterns."""
    logger.info(
        "mcp_gateway.node.detect_abuse",
        request_id=state.request_id,
        anomaly_count=len(state.traffic_anomalies),
    )

    detail = f"Analyzed {len(state.traffic_anomalies)} anomalies"
    blocked_count = sum(1 for a in state.traffic_anomalies if a.blocked)

    if state.traffic_anomalies:
        context_lines = [
            "## Traffic Anomalies Detected",
            f"Total anomalies: {len(state.traffic_anomalies)}",
            f"Already blocked: {blocked_count}",
            "",
        ]
        for a in state.traffic_anomalies:
            context_lines.append(
                f"- {a.server_id}/{a.tool_name}: type={a.anomaly_type}, "
                f"caller={a.caller_id}, requests={a.request_count}/"
                f"{a.time_window_min}min, blocked={a.blocked}"
            )

        try:
            result = cast(
                AbuseDetectionResult,
                await llm_structured(
                    system_prompt=SYSTEM_ABUSE_DETECTION,
                    user_prompt="\n".join(context_lines),
                    schema=AbuseDetectionResult,
                ),
            )
            detail = result.summary
        except Exception as exc:
            logger.error("llm_abuse_detection_failed", error=str(exc))
            detail += f" (LLM analysis failed: {exc})"

    step = ReasoningStep(
        step=len(state.reasoning_chain) + 1,
        detail=detail,
        confidence=0.82,
        metadata={
            "anomalies_analyzed": len(state.traffic_anomalies),
            "blocked": blocked_count,
        },
    )

    return {
        "stage": GatewayStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_abuse",
    }


# -------------------------------------------------------------------
# Node: generate_report
# -------------------------------------------------------------------


async def generate_report(state: MCPGatewayState) -> dict[str, Any]:
    """Compile the final gateway report with stats and reasoning chain."""
    logger.info(
        "mcp_gateway.node.generate_report",
        request_id=state.request_id,
    )

    elapsed_ms = int((time.monotonic() - state.session_start) * 1000) if state.session_start else 0

    stats: dict[str, Any] = {
        "servers_discovered": len(state.mcp_servers),
        "assessments_completed": len(state.security_assessments),
        "god_keys_found": state.god_keys_found,
        "policies_enforced": len(state.policy_enforcements),
        "anomalies_detected": len(state.traffic_anomalies),
        "anomalies_blocked": sum(1 for a in state.traffic_anomalies if a.blocked),
        "duration_ms": elapsed_ms,
    }

    step = ReasoningStep(
        step=len(state.reasoning_chain) + 1,
        detail=(
            f"Report complete: {stats['servers_discovered']} servers, "
            f"{stats['god_keys_found']} God Keys, "
            f"{stats['policies_enforced']} policies, "
            f"{stats['anomalies_detected']} anomalies"
        ),
        confidence=0.95,
        metadata=stats,
    )

    return {
        "stats": stats,
        "session_duration_ms": elapsed_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
