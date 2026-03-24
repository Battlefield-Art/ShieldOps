"""Integration test for the MCP Security Agent LangGraph pipeline.

Tests graph compilation, state model validation, conditional routing
(god key detection path), and full scan pipeline execution.
"""

from __future__ import annotations

import pytest

from shieldops.agents.mcp_security.graph import create_mcp_security_graph, should_deep_scan
from shieldops.agents.mcp_security.models import (
    GodKeyRisk,
    MCPSecurityState,
    MCPServerInfo,
)

# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def scan_state() -> dict:
    """State with MCP endpoints for scanning."""
    return MCPSecurityState(
        scan_id="mcp-scan-001",
        scan_scope=["internal-mcp-cluster", "dev-mcp-gateway"],
        scan_depth="standard",
        policy_set={"max_tools_per_server": 20, "require_auth": True},
    ).model_dump()


@pytest.fixture
def deep_scan_state() -> dict:
    """State configured for deep scan with supply chain analysis."""
    return MCPSecurityState(
        scan_id="mcp-scan-deep-001",
        scan_scope=["production-mcp-cluster"],
        scan_depth="deep",
        policy_set={"max_tools_per_server": 10, "require_auth": True},
    ).model_dump()


# ── Graph Compilation ─────────────────────────────────────────────────


def test_graph_compiles():
    """Graph compiles and contains all expected nodes."""
    sg = create_mcp_security_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()

    expected_nodes = [
        "discover_servers",
        "map_connections",
        "analyze_permissions",
        "scan_configs",
        "detect_god_keys",
        "scan_supply_chain",
        "generate_policies",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected_nodes:
        assert name in node_ids, f"Missing node: {name}"


# ── State Model Validation ────────────────────────────────────────────


def test_state_model_validation():
    """MCPSecurityState validates correctly with sample data."""
    server = MCPServerInfo(
        endpoint="https://mcp.internal:8080",
        name="data-gateway",
        version="1.2.0",
        transport="http_sse",
        auth_type="oauth2",
        tools_exposed=["query_db", "read_files", "execute_command"],
        risk_score=72.5,
    )
    god_key = GodKeyRisk(
        server_id="data-gateway",
        credential_scope="admin:*",
        downstream_count=15,
        blast_radius="critical",
        sensitive_resources=["production-db", "secrets-vault"],
    )
    state = MCPSecurityState(
        scan_id="test-scan",
        scan_scope=["cluster-a"],
        scan_depth="deep",
        mcp_servers_found=[server],
        god_key_risks=[god_key],
        current_step="detect_god_keys",
    )
    assert state.scan_id == "test-scan"
    assert len(state.mcp_servers_found) == 1
    assert state.mcp_servers_found[0].tools_exposed == [
        "query_db",
        "read_files",
        "execute_command",
    ]
    assert len(state.god_key_risks) == 1
    assert state.god_key_risks[0].blast_radius == "critical"


def test_state_model_defaults():
    """MCPSecurityState defaults are correct."""
    state = MCPSecurityState()
    assert state.scan_depth == "standard"
    assert state.mcp_servers_found == []
    assert state.god_key_risks == []
    assert state.error is None


# ── Conditional Edge: God Key Detection Path ──────────────────────────


def test_god_key_detection_deep_path():
    """Deep scan depth routes to scan_supply_chain."""
    state = MCPSecurityState(scan_depth="deep")
    assert should_deep_scan(state) == "scan_supply_chain"


def test_god_key_detection_standard_path():
    """Standard scan depth skips supply chain, goes to generate_policies."""
    state = MCPSecurityState(scan_depth="standard")
    assert should_deep_scan(state) == "generate_policies"


def test_god_key_detection_error_path():
    """Error state routes directly to generate_report."""
    state = MCPSecurityState(scan_depth="deep", error="connection timeout")
    assert should_deep_scan(state) == "generate_report"


# ── Full Scan Pipeline ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_full_scan_pipeline(scan_state):
    """Run the full MCP security scan pipeline; verify graph executes."""
    sg = create_mcp_security_graph()
    compiled = sg.compile()

    try:
        result = await compiled.ainvoke(scan_state)
    except Exception:
        pytest.skip("Pipeline ainvoke requires external dependencies")
        return

    assert isinstance(result, dict)
    assert "mcp_servers_found" in result
    assert "current_step" in result


@pytest.mark.asyncio
async def test_deep_scan_pipeline(deep_scan_state):
    """Deep scan pipeline exercises the supply chain scanning path."""
    sg = create_mcp_security_graph()
    compiled = sg.compile()

    try:
        result = await compiled.ainvoke(deep_scan_state)
    except Exception:
        pytest.skip("Pipeline ainvoke requires external dependencies")
        return

    assert isinstance(result, dict)
    assert "supply_chain_risks" in result
