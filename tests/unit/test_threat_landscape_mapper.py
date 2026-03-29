"""Tests for threat_landscape_mapper."""

from __future__ import annotations

from shieldops.agents.threat_landscape_mapper.models import (
    MappingStage,
    RelevanceLevel,
    ThreatLandscapeMapperState,
)


class TestEnums:
    def test_mappingstage(self) -> None:
        assert MappingStage.COLLECT_INTEL == "collect_intel"
        assert len(MappingStage) >= 3

    def test_relevancelevel(self) -> None:
        assert RelevanceLevel.DIRECT_THREAT == "direct_threat"
        assert len(RelevanceLevel) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = ThreatLandscapeMapperState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = ThreatLandscapeMapperState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
