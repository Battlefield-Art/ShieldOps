"""LangGraph workflow definition for the MCP Security Agent."""

import structlog
from langgraph.graph import END, StateGraph

from shieldops.agents.mcp_security.models import MCPSecurityState
from shieldops.agents.mcp_security.nodes import (
    analyze_permissions,
    detect_god_keys,
    discover_servers,
    generate_policies,
    generate_report,
    map_connections,
    scan_configs,
    scan_supply_chain,
)
from shieldops.agents.tracing import traced_node

logger = structlog.get_logger()


def should_deep_scan(state: MCPSecurityState) -> str:
    """Decide whether to do supply chain scanning based on scan depth."""
    if state.error:
        return "generate_report"
    if state.scan_depth == "deep":
        return "scan_supply_chain"
    return "generate_policies"


def create_mcp_security_graph() -> StateGraph[MCPSecurityState]:
    """Build the MCP Security Agent LangGraph workflow.

    Workflow:
        discover_servers → map_connections → analyze_permissions
            → scan_configs → detect_god_keys
            → [conditional: scan_supply_chain OR generate_policies]
            → generate_report → END
    """
    graph = StateGraph(MCPSecurityState)

    _agent = "mcp_security"
    graph.add_node(
        "discover_servers",
        traced_node("mcp_security.discover_servers", _agent)(discover_servers),
    )
    graph.add_node(
        "map_connections",
        traced_node("mcp_security.map_connections", _agent)(map_connections),
    )
    graph.add_node(
        "analyze_permissions",
        traced_node("mcp_security.analyze_permissions", _agent)(analyze_permissions),
    )
    graph.add_node(
        "scan_configs",
        traced_node("mcp_security.scan_configs", _agent)(scan_configs),
    )
    graph.add_node(
        "detect_god_keys",
        traced_node("mcp_security.detect_god_keys", _agent)(detect_god_keys),
    )
    graph.add_node(
        "scan_supply_chain",
        traced_node("mcp_security.scan_supply_chain", _agent)(scan_supply_chain),
    )
    graph.add_node(
        "generate_policies",
        traced_node("mcp_security.generate_policies", _agent)(generate_policies),
    )
    graph.add_node(
        "generate_report",
        traced_node("mcp_security.generate_report", _agent)(generate_report),
    )

    # Define edges
    graph.set_entry_point("discover_servers")
    graph.add_edge("discover_servers", "map_connections")
    graph.add_edge("map_connections", "analyze_permissions")
    graph.add_edge("analyze_permissions", "scan_configs")
    graph.add_edge("scan_configs", "detect_god_keys")
    graph.add_conditional_edges(
        "detect_god_keys",
        should_deep_scan,
        {
            "scan_supply_chain": "scan_supply_chain",
            "generate_policies": "generate_policies",
            "generate_report": "generate_report",
        },
    )
    graph.add_edge("scan_supply_chain", "generate_policies")
    graph.add_edge("generate_policies", "generate_report")
    graph.add_edge("generate_report", END)

    return graph
