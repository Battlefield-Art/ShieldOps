"""Unit tests for packet_inspector agent."""

from __future__ import annotations

from shieldops.agents.packet_inspector.models import (
    InspectionStage,
    PacketCapture,
    PacketInspectorState,
    PayloadRisk,
)
from shieldops.agents.packet_inspector.tools import PacketInspectorToolkit


class TestEnums:
    def test_inspectionstage(self) -> None:
        assert InspectionStage.CAPTURE_PACKETS == "capture_packets"
        assert len(InspectionStage) >= 3

    def test_payloadrisk(self) -> None:
        assert PayloadRisk.CRITICAL == "critical"
        assert len(PayloadRisk) >= 3


class TestState:
    def test_defaults(self) -> None:
        state = PacketInspectorState()
        assert state.request_id == ""
        assert state.error == ""

    def test_with_values(self) -> None:
        state = PacketInspectorState(
            request_id="t-1",
            tenant_id="t-1",
        )
        assert state.request_id == "t-1"


class TestPacketCapture:
    def test_defaults(self) -> None:
        obj = PacketCapture()
        assert obj is not None


class TestToolkit:
    def test_init(self) -> None:
        tk = PacketInspectorToolkit()
        assert tk is not None
