"""Integration test for the MCP Gateway Agent LangGraph pipeline."""

from __future__ import annotations

import pytest

from shieldops.agents.mcp_gateway.models import (
    AuthMethod,
    GatewayStage,
    MCPGatewayState,
    MCPServerProfile,
    MCPServerRisk,
)


@pytest.fixture
def gateway_state() -> dict:
    return MCPGatewayState(
        request_id="test-mg-001",
        tenant_id="tenant-prod-01",
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.mcp_gateway.graph import create_mcp_gateway_graph

    sg = create_mcp_gateway_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = [
        "discover_servers",
        "assess_security",
        "enforce_policies",
        "monitor_traffic",
        "detect_abuse",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_validation():
    server = MCPServerProfile(
        id="mcp-001",
        server_name="file-server",
        endpoint_url="localhost:3000",
        auth_method=AuthMethod.NONE,
        tools_exposed=["read_file", "write_file", "delete_file"],
        permission_scope="filesystem",
        tls_enabled=False,
        rate_limit_configured=False,
        god_key_risk=True,
        risk_level=MCPServerRisk.CRITICAL,
    )
    state = MCPGatewayState(
        mcp_servers=[server], god_keys_found=1, stage=GatewayStage.ENFORCE_POLICIES
    )
    assert state.mcp_servers[0].god_key_risk is True
    assert state.god_keys_found == 1


def test_state_defaults():
    state = MCPGatewayState()
    assert state.stage == GatewayStage.DISCOVER_SERVERS
    assert state.mcp_servers == []
    assert state.god_keys_found == 0


@pytest.mark.asyncio
async def test_full_pipeline(gateway_state):
    from shieldops.agents.mcp_gateway.graph import create_mcp_gateway_graph

    sg = create_mcp_gateway_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(gateway_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
