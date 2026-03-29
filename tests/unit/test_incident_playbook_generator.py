"""Tests for incident_playbook_generator."""

from __future__ import annotations

from shieldops.agents.incident_playbook_generator.models import (
    IncidentPlaybookGeneratorState,
    PlaybookComplexity,
    PlaybookStage,
    PlaybookType,
)


class TestEnums:
    def test_generator_stage(self) -> None:
        assert PlaybookStage.ANALYZE_THREAT == "analyze_threat"
        assert len(PlaybookStage) >= 3

    def test_playbook_type(self) -> None:
        assert PlaybookType.RANSOMWARE == "ransomware"
        assert len(PlaybookType) >= 3

    def test_playbook_complexity(self) -> None:
        assert PlaybookComplexity.SIMPLE == "simple"
        assert len(PlaybookComplexity) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = IncidentPlaybookGeneratorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = IncidentPlaybookGeneratorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
