"""Tests for shieldops.agents.ai_red_team."""

from __future__ import annotations

from shieldops.agents.ai_red_team.models import (
    AIRedTeamState,
)


class TestModels:
    def test_state_defaults(self):
        s = AIRedTeamState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.ai_red_team.graph import (
            create_ai_red_team_graph,
        )

        sg = create_ai_red_team_graph()
        assert sg.compile() is not None
