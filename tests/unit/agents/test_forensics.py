"""Tests for shieldops.agents.forensics."""

from __future__ import annotations

from shieldops.agents.forensics.models import (
    ForensicsState,
)


class TestModels:
    def test_state_defaults(self):
        s = ForensicsState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.forensics.graph import (
            create_forensics_graph,
        )

        sg = create_forensics_graph()
        assert sg.compile() is not None
