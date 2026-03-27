"""Tests for shieldops.agents.workflow_engine."""

from __future__ import annotations

from shieldops.agents.workflow_engine.models import (
    WorkflowEngineState,
)


class TestModels:
    def test_state_defaults(self):
        s = WorkflowEngineState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.workflow_engine.graph import (
            create_workflow_engine_graph,
        )

        sg = create_workflow_engine_graph()
        assert sg.compile() is not None
