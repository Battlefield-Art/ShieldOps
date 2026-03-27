"""Tests for shieldops.agents.situation_composer."""

from __future__ import annotations

from shieldops.agents.situation_composer.models import (
    SituationComposerState,
)


class TestModels:
    def test_state_defaults(self):
        s = SituationComposerState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.situation_composer.graph import (
            create_situation_composer_graph,
        )

        sg = create_situation_composer_graph()
        assert sg.compile() is not None
