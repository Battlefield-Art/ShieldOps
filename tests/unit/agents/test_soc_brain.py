"""Tests for shieldops.agents.soc_brain."""

from __future__ import annotations

from shieldops.agents.soc_brain.models import (
    SOCBrainState,
)


class TestModels:
    def test_state_defaults(self):
        s = SOCBrainState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.soc_brain.graph import (
            create_soc_brain_graph,
        )

        sg = create_soc_brain_graph()
        assert sg.compile() is not None
