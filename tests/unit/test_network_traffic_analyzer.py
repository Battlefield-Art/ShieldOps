"""Unit tests for network_traffic_analyzer agent."""

from __future__ import annotations

from shieldops.agents.network_traffic_analyzer.models import (
    AnalysisStage,
    AnomalyDetection,
    NetworkTrafficAnalyzerState,
    ProtocolType,
)
from shieldops.agents.network_traffic_analyzer.tools import NetworkTrafficAnalyzerToolkit


class TestEnums:
    def test_analysisstage(self) -> None:
        assert AnalysisStage.INGEST_FLOWS == "ingest_flows"
        assert len(AnalysisStage) >= 3

    def test_protocoltype(self) -> None:
        assert ProtocolType.TCP == "tcp"
        assert len(ProtocolType) >= 3


class TestState:
    def test_defaults(self) -> None:
        state = NetworkTrafficAnalyzerState()
        assert state.request_id == ""
        assert state.error == ""

    def test_with_values(self) -> None:
        state = NetworkTrafficAnalyzerState(
            request_id="t-1",
            tenant_id="t-1",
        )
        assert state.request_id == "t-1"


class TestAnomalyDetection:
    def test_defaults(self) -> None:
        obj = AnomalyDetection()
        assert obj is not None


class TestToolkit:
    def test_init(self) -> None:
        tk = NetworkTrafficAnalyzerToolkit()
        assert tk is not None
