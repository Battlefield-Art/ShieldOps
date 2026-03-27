"""Tests for shieldops.agents.credential_tester."""

from __future__ import annotations

from shieldops.agents.credential_tester.models import (
    CredentialTesterState,
)


class TestModels:
    def test_state_defaults(self):
        s = CredentialTesterState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.credential_tester.graph import (
            create_credential_tester_graph,
        )

        sg = create_credential_tester_graph()
        assert sg.compile() is not None
