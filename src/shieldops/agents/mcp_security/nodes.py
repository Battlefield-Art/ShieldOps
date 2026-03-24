"""Node implementations for the MCP Security Agent LangGraph workflow.

Each node is an async function that:
1. Uses the MCPSecurityToolkit to query engines
2. Uses the LLM to analyze and reason about findings
3. Updates the scan state with results
4. Records its reasoning step in the audit trail
"""

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.mcp_security.models import (
    GodKeyRisk,
    MCPSecurityState,
    MCPServerInfo,
    MCPVulnerability,
    ReasoningStep,
)
from shieldops.agents.mcp_security.prompts import (
    SYSTEM_GOD_KEY_ANALYSIS,
    SYSTEM_MCP_POLICY_GENERATION,
    SYSTEM_MCP_SECURITY_AUDIT,
    GodKeyAnalysisResult,
    PolicyGenerationResult,
    VulnerabilityAssessmentResult,
)
from shieldops.agents.mcp_security.tools import MCPSecurityToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

# Module-level toolkit reference, set by the runner at graph construction time.
_toolkit: MCPSecurityToolkit | None = None


def set_toolkit(toolkit: MCPSecurityToolkit) -> None:
    """Configure the toolkit used by all nodes. Called once at startup."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> MCPSecurityToolkit:
    if _toolkit is None:
        return MCPSecurityToolkit()
    return _toolkit


async def discover_servers(state: MCPSecurityState) -> dict[str, Any]:
    """Discover MCP servers from the scan scope endpoints."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info("mcp_security.discovering_servers", scan_id=state.scan_id, scope=state.scan_scope)

    raw_servers = await toolkit.discover_mcp_servers(state.scan_scope)

    servers: list[MCPServerInfo] = []
    for s in raw_servers:
        servers.append(
            MCPServerInfo(
                endpoint=s.get("endpoint", ""),
                name=s.get("name", ""),
                version=s.get("version", "unknown"),
                transport=s.get("transport", "http_sse"),
                auth_type=s.get("auth_type", "none"),
            )
        )

    step = ReasoningStep(
        step_number=1,
        action="discover_servers",
        input_summary=f"Scanning {len(state.scan_scope)} endpoints",
        output_summary=f"Discovered {len(servers)} MCP servers",
        duration_ms=_elapsed_ms(start),
        tool_used="discover_mcp_servers",
    )

    return {
        "mcp_servers_found": servers,
        "reasoning_chain": [step],
        "current_step": "discover_servers",
        "scan_start": start,
    }


async def map_connections(state: MCPSecurityState) -> dict[str, Any]:
    """Map connections and downstream resources for each discovered server."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info("mcp_security.mapping_connections", server_count=len(state.mcp_servers_found))

    connections: list[dict[str, Any]] = []
    for server in state.mcp_servers_found:
        server_id = server.endpoint.replace("https://", "").replace("http://", "").replace("/", "_")
        result = await toolkit.map_downstream_resources(
            server_id=server_id,
            server_name=server.name,
            endpoint=server.endpoint,
            tools=server.tools_exposed,
            resources=[],
        )
        connections.append(result)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="map_connections",
        input_summary=f"Mapping connections for {len(state.mcp_servers_found)} servers",
        output_summary=f"Mapped {len(connections)} server connections",
        duration_ms=_elapsed_ms(start),
        tool_used="map_downstream_resources",
    )

    return {
        "connections_mapped": connections,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "map_connections",
    }


async def analyze_permissions(state: MCPSecurityState) -> dict[str, Any]:
    """Analyze authentication and permission configuration for each server."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info("mcp_security.analyzing_permissions", server_count=len(state.mcp_servers_found))

    permissions: list[dict[str, Any]] = []
    excessive: list[dict[str, Any]] = []
    for server in state.mcp_servers_found:
        server_id = server.endpoint.replace("https://", "").replace("http://", "").replace("/", "_")
        auth_result = await toolkit.check_auth_configuration(server_id, server.auth_type)
        permissions.append(auth_result)
        if auth_result.get("issues"):
            excessive.append(
                {
                    "server_id": server_id,
                    "auth_type": server.auth_type,
                    "issues": auth_result["issues"],
                }
            )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="analyze_permissions",
        input_summary=f"Checking auth for {len(state.mcp_servers_found)} servers",
        output_summary=f"Found {len(excessive)} servers with permission issues",
        duration_ms=_elapsed_ms(start),
        tool_used="check_auth_configuration",
    )

    return {
        "permissions_analyzed": permissions,
        "excessive_permissions": excessive,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_permissions",
    }


async def scan_configs(state: MCPSecurityState) -> dict[str, Any]:
    """Scan MCP server configurations for vulnerabilities using the LLM."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info("mcp_security.scanning_configs", server_count=len(state.mcp_servers_found))

    vulnerabilities: list[MCPVulnerability] = []
    for server in state.mcp_servers_found:
        server_id = server.endpoint.replace("https://", "").replace("http://", "").replace("/", "_")
        config_result = await toolkit.analyze_server_config(server_id, server.endpoint)
        for vuln in config_result.get("vulnerabilities", []):
            vulnerabilities.append(
                MCPVulnerability(
                    server_id=server_id,
                    vuln_type=vuln.get("type", ""),
                    severity=vuln.get("severity", "medium"),
                    description=vuln.get("description", ""),
                    remediation=vuln.get("remediation", ""),
                )
            )

    # LLM-powered assessment
    output_summary = f"Found {len(vulnerabilities)} config vulnerabilities"
    if state.mcp_servers_found:
        context_lines = [
            "## MCP Server Configurations",
            f"Servers scanned: {len(state.mcp_servers_found)}",
            "",
        ]
        for server in state.mcp_servers_found:
            context_lines.append(
                f"- {server.name}: transport={server.transport}, auth={server.auth_type}"
            )
        for vuln in vulnerabilities:
            context_lines.append(f"- [{vuln.severity}] {vuln.description}")

        try:
            result = cast(
                VulnerabilityAssessmentResult,
                await llm_structured(
                    system_prompt=SYSTEM_MCP_SECURITY_AUDIT,
                    user_prompt="\n".join(context_lines),
                    schema=VulnerabilityAssessmentResult,
                ),
            )
            output_summary = result.summary
            for finding in result.critical_findings:
                vulnerabilities.append(
                    MCPVulnerability(
                        server_id="llm_analysis",
                        vuln_type="llm_detected",
                        severity="critical",
                        description=finding,
                    )
                )
        except Exception as e:
            logger.error("llm_vuln_assessment_failed", error=str(e))
            output_summary += f" (LLM analysis failed: {e})"

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="scan_configs",
        input_summary=f"Scanning configs for {len(state.mcp_servers_found)} servers",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="analyze_server_config + llm",
    )

    return {
        "config_vulnerabilities": vulnerabilities,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "scan_configs",
    }


async def detect_god_keys(state: MCPSecurityState) -> dict[str, Any]:
    """Detect God Key risks using connection registry and LLM analysis."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info("mcp_security.detecting_god_keys", scan_id=state.scan_id)

    raw_god_keys = toolkit.registry.detect_god_keys()
    god_keys: list[GodKeyRisk] = []
    for gk in raw_god_keys:
        god_keys.append(
            GodKeyRisk(
                server_id=gk["server_id"],
                credential_scope=(
                    f"{gk['downstream_count']} resources via {len(gk['tools_exposed'])} tools"
                ),
                downstream_count=gk["downstream_count"],
                blast_radius="critical" if gk["downstream_count"] >= 10 else "high",
            )
        )

    # LLM analysis of God Key risks
    output_summary = f"Found {len(god_keys)} God Key risks"
    if god_keys or state.connections_mapped:
        context_lines = [
            "## Connection Map",
            f"Total connections: {len(state.connections_mapped)}",
            "",
            "## God Key Candidates",
        ]
        for gk in god_keys:
            context_lines.append(
                f"- {gk.server_id}: {gk.downstream_count} downstream, scope={gk.credential_scope}"
            )
        for conn in state.connections_mapped:
            context_lines.append(
                f"- Server {conn.get('server_id', '?')}: risk={conn.get('risk_score', 0)}"
            )

        try:
            result = cast(
                GodKeyAnalysisResult,
                await llm_structured(
                    system_prompt=SYSTEM_GOD_KEY_ANALYSIS,
                    user_prompt="\n".join(context_lines),
                    schema=GodKeyAnalysisResult,
                ),
            )
            output_summary = result.blast_radius_summary
        except Exception as e:
            logger.error("llm_god_key_analysis_failed", error=str(e))
            output_summary += f" (LLM analysis failed: {e})"

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="detect_god_keys",
        input_summary="Analyzing connection graph for God Key patterns",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="connection_registry + llm",
    )

    return {
        "god_key_risks": god_keys,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_god_keys",
    }


async def scan_supply_chain(state: MCPSecurityState) -> dict[str, Any]:
    """Scan MCP server supply chain dependencies."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info("mcp_security.scanning_supply_chain", server_count=len(state.mcp_servers_found))

    supply_chain_risks: list[dict[str, Any]] = []
    for server in state.mcp_servers_found:
        server_id = server.endpoint.replace("https://", "").replace("http://", "").replace("/", "_")
        results = await toolkit.scan_dependencies(server_id, components=[])
        if results:
            supply_chain_risks.extend(results)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="scan_supply_chain",
        input_summary=f"Scanning dependencies for {len(state.mcp_servers_found)} servers",
        output_summary=f"Found {len(supply_chain_risks)} supply chain items",
        duration_ms=_elapsed_ms(start),
        tool_used="scan_dependencies",
    )

    return {
        "supply_chain_risks": supply_chain_risks,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "scan_supply_chain",
    }


async def generate_policies(state: MCPSecurityState) -> dict[str, Any]:
    """Generate zero-trust policies based on findings using the LLM."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info("mcp_security.generating_policies", scan_id=state.scan_id)

    policies: list[dict[str, Any]] = []
    output_summary = "Generating policies"

    # Build context from all findings
    context_lines = [
        "## Discovered Servers",
        f"Count: {len(state.mcp_servers_found)}",
        "",
        "## Vulnerabilities Found",
    ]
    for vuln in state.config_vulnerabilities:
        context_lines.append(f"- [{vuln.severity}] {vuln.description}")
    context_lines.append("")
    context_lines.append("## God Key Risks")
    for gk in state.god_key_risks:
        context_lines.append(
            f"- {gk.server_id}: {gk.downstream_count} downstream, blast_radius={gk.blast_radius}"
        )
    context_lines.append("")
    context_lines.append("## Permission Issues")
    for perm in state.excessive_permissions:
        context_lines.append(f"- {perm.get('server_id', '?')}: {perm.get('issues', [])}")

    try:
        result = cast(
            PolicyGenerationResult,
            await llm_structured(
                system_prompt=SYSTEM_MCP_POLICY_GENERATION,
                user_prompt="\n".join(context_lines),
                schema=PolicyGenerationResult,
            ),
        )
        n_pol = len(result.policies)
        reduction = result.estimated_risk_reduction
        output_summary = f"Generated {n_pol} policies. Risk reduction: {reduction}"
        for i, pol in enumerate(result.policies):
            policies.append(
                {
                    "priority": i + 1,
                    "description": pol,
                    "enforcement_action": result.enforcement_actions[i]
                    if i < len(result.enforcement_actions)
                    else "audit_only",
                }
            )
    except Exception as e:
        logger.error("llm_policy_generation_failed", error=str(e))
        output_summary = f"Policy generation failed: {e}"
        # Fallback: generate basic policies
        for server in state.mcp_servers_found:
            server_id = (
                server.endpoint.replace("https://", "").replace("http://", "").replace("/", "_")
            )
            await toolkit.generate_zero_trust_policy(server_id)
            policies.append(
                {
                    "priority": len(policies) + 1,
                    "description": f"Apply zero-trust defaults to {server.name}",
                    "enforcement_action": "require_oauth2",
                }
            )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_policies",
        input_summary="Synthesizing findings into zero-trust policies",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="llm + generate_zero_trust_policy",
    )

    return {
        "policies_generated": policies,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "generate_policies",
    }


async def generate_report(state: MCPSecurityState) -> dict[str, Any]:
    """Generate final scan report and create alerts for critical findings."""
    start = datetime.now(UTC)

    logger.info("mcp_security.generating_report", scan_id=state.scan_id)

    alerts: list[dict[str, Any]] = []

    # Create alerts for critical vulnerabilities
    for vuln in state.config_vulnerabilities:
        if vuln.severity == "critical":
            alerts.append(
                {
                    "type": "mcp_critical_vulnerability",
                    "server_id": vuln.server_id,
                    "description": vuln.description,
                    "severity": "critical",
                }
            )

    # Create alerts for God Keys
    for gk in state.god_key_risks:
        alerts.append(
            {
                "type": "mcp_god_key_detected",
                "server_id": gk.server_id,
                "downstream_count": gk.downstream_count,
                "blast_radius": gk.blast_radius,
                "severity": "high",
            }
        )

    scan_duration = (
        int((datetime.now(UTC) - state.scan_start).total_seconds() * 1000)
        if state.scan_start
        else 0
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary="Compiling final scan report",
        output_summary=(
            f"Report complete: {len(state.config_vulnerabilities)} vulns, "
            f"{len(state.god_key_risks)} god keys, "
            f"{len(state.policies_generated)} policies, "
            f"{len(alerts)} alerts"
        ),
        duration_ms=_elapsed_ms(start),
        tool_used=None,
    )

    return {
        "alerts_created": alerts,
        "scan_duration_ms": scan_duration,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }


# --- helpers ---


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)
