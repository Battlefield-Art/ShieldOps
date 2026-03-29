"""Tests for threat_brief_generator."""

from __future__ import annotations

from shieldops.agents.threat_brief_generator.models import (
    AudienceType,
    BriefPriority,
    BriefStage,
    ThreatBriefGeneratorState,
)


class TestEnums:
    def test_audiencetype(self) -> None:
        assert AudienceType.EXECUTIVE == "executive"
        assert len(AudienceType) >= 3

    def test_briefpriority(self) -> None:
        assert BriefPriority.FLASH == "flash"
        assert len(BriefPriority) >= 3

    def test_briefstage(self) -> None:
        assert BriefStage.COLLECT_INTEL == "collect_intel"
        assert len(BriefStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = ThreatBriefGeneratorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = ThreatBriefGeneratorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
