"""Tests for access_remediation."""

from __future__ import annotations

from shieldops.agents.access_remediation.models import (
    AccessRemediationState,
)


class TestModels:
    def test_state_defaults(self):
        s = AccessRemediationState(tenant_id="t")
        assert s.error == ""


class TestGraph:
    def test_compiles(self):
        from shieldops.agents.access_remediation.graph import create_access_remediation_graph

        assert create_access_remediation_graph().compile() is not None
