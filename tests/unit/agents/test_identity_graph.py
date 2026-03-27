"""Tests for shieldops.agents.identity_graph."""

from __future__ import annotations

from shieldops.agents.identity_graph.models import (
    IdentityGraphState,
)


class TestModels:
    def test_state_defaults(self):
        s = IdentityGraphState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.identity_graph.graph import (
            create_identity_graph,
        )

        sg = create_identity_graph()
        assert sg.compile() is not None
