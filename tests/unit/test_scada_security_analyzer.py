"""Tests for scada_security_analyzer."""

from __future__ import annotations

from shieldops.agents.scada_security_analyzer.models import (
    AnalysisStage,
    ProtocolType,
    SCADASecurityAnalyzerState,
)


class TestEnums:
    def test_analysisstage(self) -> None:
        assert AnalysisStage.DISCOVER_ASSETS == "discover_assets"
        assert len(AnalysisStage) >= 3

    def test_protocoltype(self) -> None:
        assert ProtocolType.MODBUS == "modbus"
        assert len(ProtocolType) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = SCADASecurityAnalyzerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = SCADASecurityAnalyzerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
