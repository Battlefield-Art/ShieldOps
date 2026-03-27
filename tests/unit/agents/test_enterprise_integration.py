"""Tests for shieldops.agents.enterprise_integration."""

from __future__ import annotations

from shieldops.agents.enterprise_integration.models import (
    IntegrationState,
)


class TestModels:
    def test_state_exists(self):
        assert IntegrationState is not None


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.enterprise_integration.graph import (
            create_integration_graph,
        )

        sg = create_integration_graph()
        assert sg.compile() is not None
