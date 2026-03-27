"""Tests for shieldops.agents.mcp_gateway."""

from __future__ import annotations

from shieldops.agents.mcp_gateway.models import (
    MCPGatewayState,
)


class TestModels:
    def test_state_defaults(self):
        s = MCPGatewayState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.mcp_gateway.graph import (
            create_mcp_gateway_graph,
        )

        sg = create_mcp_gateway_graph()
        assert sg.compile() is not None
