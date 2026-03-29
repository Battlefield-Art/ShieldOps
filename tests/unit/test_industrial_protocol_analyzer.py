"""Tests for industrial_protocol_analyzer."""

from __future__ import annotations

from shieldops.agents.industrial_protocol_analyzer.models import (
    IndustrialProtocol,
    IndustrialProtocolAnalyzerState,
    InspectionStage,
    PacketRisk,
)


class TestEnums:
    def test_industrialprotocol(self) -> None:
        assert IndustrialProtocol.MODBUS_TCP == "modbus_tcp"
        assert len(IndustrialProtocol) >= 3

    def test_inspectionstage(self) -> None:
        assert InspectionStage.CAPTURE_TRAFFIC == "capture_traffic"
        assert len(InspectionStage) >= 3

    def test_packetrisk(self) -> None:
        assert PacketRisk.SAFE == "safe"
        assert len(PacketRisk) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = IndustrialProtocolAnalyzerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = IndustrialProtocolAnalyzerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
