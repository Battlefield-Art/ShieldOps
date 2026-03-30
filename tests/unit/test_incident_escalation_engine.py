"""Tests for incident_escalation_engine."""

from __future__ import annotations

from shieldops.agents.incident_escalation_engine.models import (
    EscalationTier,
    IEEStage,
    IncidentEscalationEngineState,
    UrgencyLevel,
)


class TestEnums:
    def test_stage(self) -> None:
        assert IEEStage.ASSESS_SEVERITY == "assess_severity"
        assert len(IEEStage) >= 3

    def test_escalation_tier(self) -> None:
        assert EscalationTier.TIER_1 == "tier_1"
        assert len(EscalationTier) >= 3

    def test_urgency_level(self) -> None:
        assert UrgencyLevel.IMMEDIATE == "immediate"
        assert len(UrgencyLevel) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = IncidentEscalationEngineState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = IncidentEscalationEngineState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
