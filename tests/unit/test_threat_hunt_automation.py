"""Tests for threat_hunt_automation."""

from __future__ import annotations

from shieldops.agents.threat_hunt_automation.models import (
    HuntOutcome,
    HuntTechnique,
    THAStage,
    ThreatHuntAutomationState,
)


class TestEnums:
    def test_stage(self) -> None:
        assert THAStage.GENERATE_HYPOTHESES == "generate_hypotheses"
        assert len(THAStage) >= 3

    def test_hunt_technique(self) -> None:
        assert HuntTechnique.BEHAVIORAL_ANALYSIS == "behavioral_analysis"
        assert len(HuntTechnique) >= 3

    def test_hunt_outcome(self) -> None:
        assert HuntOutcome.CONFIRMED_THREAT == "confirmed_threat"
        assert len(HuntOutcome) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = ThreatHuntAutomationState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = ThreatHuntAutomationState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
