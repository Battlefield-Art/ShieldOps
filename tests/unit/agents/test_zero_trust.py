"""Tests for shieldops.agents.zero_trust."""

from __future__ import annotations

from shieldops.agents.zero_trust.models import (
    ZeroTrustState,
)


class TestModels:
    def test_state_defaults(self):
        s = ZeroTrustState()
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.zero_trust.graph import (
            create_zero_trust_graph,
        )

        sg = create_zero_trust_graph()
        assert sg.compile() is not None
