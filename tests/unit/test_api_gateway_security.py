"""Tests for api_gateway_security."""

from __future__ import annotations

from shieldops.agents.api_gateway_security.models import (
    AbuseType,
    AGSStage,
    APIGatewaySecurityState,
    EndpointRisk,
)


class TestEnums:
    def test_stage(self) -> None:
        assert AGSStage.SCAN_ENDPOINTS == "scan_endpoints"
        assert len(AGSStage) >= 3

    def test_endpoint_risk(self) -> None:
        assert EndpointRisk.EXPOSED == "exposed"
        assert len(EndpointRisk) >= 3

    def test_abuse_type(self) -> None:
        assert AbuseType.BRUTE_FORCE == "brute_force"
        assert len(AbuseType) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = APIGatewaySecurityState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = APIGatewaySecurityState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
