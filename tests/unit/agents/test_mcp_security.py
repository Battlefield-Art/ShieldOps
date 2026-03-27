"""Tests for shieldops.agents.mcp_security."""

from __future__ import annotations

from shieldops.agents.mcp_security.models import (
    MCPSecurityState,
)


class TestModels:
    def test_state_defaults(self):
        s = MCPSecurityState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.mcp_security.graph import (
            create_mcp_security_graph,
        )

        sg = create_mcp_security_graph()
        assert sg.compile() is not None
