"""Tests for shieldops.agents.ai_blue_team."""

from __future__ import annotations

from shieldops.agents.ai_blue_team.models import (
    AIBlueTeamState,
)


class TestModels:
    def test_state_defaults(self):
        s = AIBlueTeamState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.ai_blue_team.graph import (
            create_ai_blue_team_graph,
        )

        sg = create_ai_blue_team_graph()
        assert sg.compile() is not None
