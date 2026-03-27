"""Tests for remediation_verifier."""

from __future__ import annotations

from shieldops.agents.remediation_verifier.models import (
    RemediationVerifierState,
)


class TestModels:
    def test_state_defaults(self):
        s = RemediationVerifierState(tenant_id="t")
        assert s.error == ""


class TestGraph:
    def test_compiles(self):
        from shieldops.agents.remediation_verifier.graph import create_remediation_verifier_graph

        assert create_remediation_verifier_graph().compile() is not None
