"""Tests for shieldops.agents.finops_intelligence."""

from __future__ import annotations

from shieldops.agents.finops_intelligence.models import (
    FinOpsIntelligenceState,
)


class TestModels:
    def test_state_defaults(self):
        s = FinOpsIntelligenceState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.finops_intelligence.graph import (
            create_finops_intelligence_graph,
        )

        sg = create_finops_intelligence_graph()
        assert sg.compile() is not None
