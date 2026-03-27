"""Tests for shieldops.agents.ai_soc_assistant."""

from __future__ import annotations

from shieldops.agents.ai_soc_assistant.models import (
    AISOCAssistantState,
)


class TestModels:
    def test_state_defaults(self):
        s = AISOCAssistantState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.ai_soc_assistant.graph import (
            create_ai_soc_assistant_graph,
        )

        sg = create_ai_soc_assistant_graph()
        assert sg.compile() is not None
