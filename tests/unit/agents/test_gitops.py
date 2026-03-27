"""Tests for shieldops.agents.gitops."""

from __future__ import annotations

from shieldops.agents.gitops.models import (
    GitOpsState,
)


class TestModels:
    def test_state_defaults(self):
        s = GitOpsState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.gitops.graph import (
            create_gitops_graph,
        )

        sg = create_gitops_graph()
        assert sg.compile() is not None
