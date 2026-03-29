"""Tests for email_gateway_analyzer."""

from __future__ import annotations

from shieldops.agents.email_gateway_analyzer.models import (
    AuthProtocol,
    GatewayAnalyzerState,
    GatewayStage,
)


class TestEnums:
    def test_authprotocol(self) -> None:
        assert AuthProtocol.SPF == "spf"
        assert len(AuthProtocol) >= 3

    def test_gatewaystage(self) -> None:
        assert GatewayStage.COLLECT_RECORDS == "collect_records"
        assert len(GatewayStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = GatewayAnalyzerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = GatewayAnalyzerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
