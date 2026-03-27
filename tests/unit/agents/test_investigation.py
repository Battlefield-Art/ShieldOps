"""Tests for shieldops.agents.investigation."""

from __future__ import annotations

from shieldops.agents.investigation.models import (
    InvestigationState,
)


class TestModels:
    def test_state_exists(self):
        assert InvestigationState is not None


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.investigation.graph import (
            create_investigation_graph,
        )

        sg = create_investigation_graph()
        assert sg.compile() is not None
