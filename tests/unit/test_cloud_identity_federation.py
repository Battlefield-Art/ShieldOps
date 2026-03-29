"""Tests for cloud_identity_federation."""

from __future__ import annotations

from shieldops.agents.cloud_identity_federation.models import (
    CloudIdentityFederationState,
    FederationRisk,
    FederationStage,
    IdentityProvider,
)


class TestEnums:
    def test_federationrisk(self) -> None:
        assert FederationRisk.CRITICAL == "critical"
        assert len(FederationRisk) >= 3

    def test_federationstage(self) -> None:
        assert FederationStage.DISCOVER_IDENTITIES == "discover_identities"
        assert len(FederationStage) >= 3

    def test_identityprovider(self) -> None:
        assert IdentityProvider.OKTA == "okta"
        assert len(IdentityProvider) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = CloudIdentityFederationState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = CloudIdentityFederationState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
