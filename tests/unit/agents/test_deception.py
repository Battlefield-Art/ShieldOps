"""Tests for shieldops.agents.deception."""

from __future__ import annotations

from shieldops.agents.deception.models import (
    DeceptionState,
)


class TestModels:
    def test_state_defaults(self):
        s = DeceptionState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.deception.graph import (
            create_deception_graph,
        )

        sg = create_deception_graph()
        assert sg.compile() is not None
