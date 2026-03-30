"""Tests for evidence_automation_engine."""

from __future__ import annotations

from shieldops.agents.evidence_automation_engine.models import (
    EAEStage,
    EvidenceAutomationEngineState,
    EvidenceType,
    ValidationStatus,
)


class TestEnums:
    def test_stage(self) -> None:
        assert EAEStage.IDENTIFY_REQUIREMENTS == "identify_requirements"
        assert len(EAEStage) >= 3

    def test_evidence_type(self) -> None:
        assert EvidenceType.SCREENSHOT == "screenshot"
        assert len(EvidenceType) >= 3

    def test_validation_status(self) -> None:
        assert ValidationStatus.VERIFIED == "verified"
        assert len(ValidationStatus) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = EvidenceAutomationEngineState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = EvidenceAutomationEngineState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
