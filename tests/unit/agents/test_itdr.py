"""Tests for shieldops.agents.itdr."""

from __future__ import annotations

from shieldops.agents.itdr.models import (
    ITDRState,
)


class TestModels:
    def test_state_defaults(self):
        s = ITDRState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.itdr.graph import (
            create_itdr_graph,
        )

        sg = create_itdr_graph()
        assert sg.compile() is not None
