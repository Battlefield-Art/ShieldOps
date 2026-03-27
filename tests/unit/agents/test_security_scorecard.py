"""Tests for security_scorecard."""

from __future__ import annotations

from shieldops.agents.security_scorecard.models import (
    SecurityScorecardState,
)


class TestModels:
    def test_state_defaults(self):
        s = SecurityScorecardState(tenant_id="t")
        assert s.error == ""


class TestGraph:
    def test_compiles(self):
        from shieldops.agents.security_scorecard.graph import create_security_scorecard_graph

        assert create_security_scorecard_graph().compile() is not None
