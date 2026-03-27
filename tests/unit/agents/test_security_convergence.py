"""Tests for shieldops.agents.security_convergence."""

from __future__ import annotations

from shieldops.agents.security_convergence.models import (
    SecurityConvergenceState,
)


class TestModels:
    def test_state_defaults(self):
        s = SecurityConvergenceState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.security_convergence.graph import (
            create_security_convergence_graph,
        )

        sg = create_security_convergence_graph()
        assert sg.compile() is not None
