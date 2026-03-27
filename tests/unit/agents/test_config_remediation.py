"""Tests for config_remediation."""

from __future__ import annotations

from shieldops.agents.config_remediation.models import (
    ConfigRemediationState,
)


class TestModels:
    def test_state_defaults(self):
        s = ConfigRemediationState(tenant_id="t")
        assert s.error == ""


class TestGraph:
    def test_compiles(self):
        from shieldops.agents.config_remediation.graph import create_config_remediation_graph

        assert create_config_remediation_graph().compile() is not None
