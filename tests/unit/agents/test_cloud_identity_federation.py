"""Tests for shieldops.agents.cloud_identity_federation."""

from __future__ import annotations

from shieldops.agents.cloud_identity_federation.models import (
    CloudIdentityFederationState,
    FederationRisk,
    FederationStage,
    IdentityProvider,
)


class TestEnums:
    def test_stage_discover(self):
        assert FederationStage.DISCOVER_IDENTITIES == "discover_identities"

    def test_stage_map(self):
        assert FederationStage.MAP_FEDERATIONS == "map_federations"

    def test_stage_misconfigs(self):
        assert FederationStage.DETECT_MISCONFIGS == "detect_misconfigs"

    def test_stage_trust(self):
        assert FederationStage.ANALYZE_TRUST == "analyze_trust"

    def test_stage_risk(self):
        assert FederationStage.ASSESS_RISK == "assess_risk"

    def test_stage_report(self):
        assert FederationStage.REPORT == "report"

    def test_idp_okta(self):
        assert IdentityProvider.OKTA == "okta"

    def test_idp_azure_ad(self):
        assert IdentityProvider.AZURE_AD == "azure_ad"

    def test_idp_google(self):
        assert IdentityProvider.GOOGLE_WORKSPACE == "google_workspace"

    def test_risk_critical(self):
        assert FederationRisk.CRITICAL == "critical"

    def test_risk_high(self):
        assert FederationRisk.HIGH == "high"

    def test_risk_medium(self):
        assert FederationRisk.MEDIUM == "medium"


class TestState:
    def test_state_defaults(self):
        s = CloudIdentityFederationState()
        assert s.error == ""

    def test_state_request_id(self):
        s = CloudIdentityFederationState()
        assert s.request_id == ""

    def test_state_stage(self):
        s = CloudIdentityFederationState()
        assert s.stage == FederationStage.DISCOVER_IDENTITIES


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.cloud_identity_federation.graph import (
            create_cloud_identity_federation_graph,
        )

        sg = create_cloud_identity_federation_graph()
        assert sg.compile() is not None
