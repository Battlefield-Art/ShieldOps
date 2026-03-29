"""Unit tests for network_forensics agent."""

from __future__ import annotations

from shieldops.agents.network_forensics.models import (
    EvidenceType,
    ExfilPath,
    ForensicsStage,
    NetworkForensicsState,
    SessionType,
)
from shieldops.agents.network_forensics.tools import NetworkForensicsToolkit


class TestEnums:
    def test_evidencetype(self) -> None:
        assert EvidenceType.PCAP == "pcap"
        assert len(EvidenceType) >= 3

    def test_forensicsstage(self) -> None:
        assert ForensicsStage.INGEST_CAPTURE == "ingest_capture"
        assert len(ForensicsStage) >= 3

    def test_sessiontype(self) -> None:
        assert SessionType.HTTP == "http"
        assert len(SessionType) >= 3


class TestState:
    def test_defaults(self) -> None:
        state = NetworkForensicsState()
        assert state.request_id == ""
        assert state.error == ""

    def test_with_values(self) -> None:
        state = NetworkForensicsState(
            request_id="t-1",
            tenant_id="t-1",
        )
        assert state.request_id == "t-1"


class TestExfilPath:
    def test_defaults(self) -> None:
        obj = ExfilPath()
        assert obj is not None


class TestToolkit:
    def test_init(self) -> None:
        tk = NetworkForensicsToolkit()
        assert tk is not None
