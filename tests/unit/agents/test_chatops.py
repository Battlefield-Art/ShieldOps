"""Tests for shieldops.agents.chatops."""

from __future__ import annotations

from shieldops.agents.chatops.models import (
    ChatOpsState,
)


class TestModels:
    def test_state_defaults(self):
        s = ChatOpsState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.chatops.graph import (
            create_chatops_graph,
        )

        sg = create_chatops_graph()
        assert sg.compile() is not None
