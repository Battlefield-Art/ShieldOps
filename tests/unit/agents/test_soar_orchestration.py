"""Tests for shieldops.agents.soar_orchestration."""

from __future__ import annotations

from shieldops.agents.soar_orchestration.models import (
    SOAROrchestrationState,
)


class TestModels:
    def test_state_defaults(self):
        s = SOAROrchestrationState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.soar_orchestration.graph import (
            create_soar_orchestration_graph,
        )

        sg = create_soar_orchestration_graph()
        assert sg.compile() is not None
