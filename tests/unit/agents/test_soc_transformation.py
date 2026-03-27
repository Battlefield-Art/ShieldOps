"""Tests for shieldops.agents.soc_transformation."""

from __future__ import annotations

from shieldops.agents.soc_transformation.models import (
    SOCTransformationState,
)


class TestModels:
    def test_state_defaults(self):
        s = SOCTransformationState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.soc_transformation.graph import (
            create_soc_transformation_graph,
        )

        sg = create_soc_transformation_graph()
        assert sg.compile() is not None
