"""Tests for shieldops.agents.learning."""

from __future__ import annotations

from shieldops.agents.learning.models import (
    LearningState,
)


class TestModels:
    def test_state_defaults(self):
        s = LearningState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.learning.graph import (
            create_learning_graph,
        )

        sg = create_learning_graph()
        assert sg.compile() is not None
