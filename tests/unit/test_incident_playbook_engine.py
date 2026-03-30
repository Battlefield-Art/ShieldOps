"""Unit tests for incident_playbook_engine agent models."""

from __future__ import annotations

from shieldops.agents.incident_playbook_engine.models import (
    IncidentCategory,
    IncidentPlaybookEngineState,
    IPEStage,
    PlaybookStatus,
)


class TestEnums:
    def test_ipe_stage_values(self) -> None:
        assert IPEStage.CLASSIFY_INCIDENT == "classify_incident"
        assert IPEStage.EXECUTE_PLAYBOOK == "execute_playbook"
        assert IPEStage.REPORT == "report"

    def test_incident_category_values(self) -> None:
        assert IncidentCategory.MALWARE == "malware"
        assert IncidentCategory.PHISHING == "phishing"
        assert IncidentCategory.RANSOMWARE == "ransomware"

    def test_playbook_status_values(self) -> None:
        assert PlaybookStatus.ACTIVE == "active"
        assert PlaybookStatus.EXECUTING == "executing"
        assert PlaybookStatus.COMPLETED == "completed"


class TestState:
    def test_default_state(self) -> None:
        state = IncidentPlaybookEngineState()
        assert state.request_id == ""
        assert state.stage == IPEStage.CLASSIFY_INCIDENT
        assert state.error == ""

    def test_state_with_values(self) -> None:
        state = IncidentPlaybookEngineState(
            request_id="req-001",
            tenant_id="t-001",
            stage=IPEStage.EXECUTE_PLAYBOOK,
        )
        assert state.request_id == "req-001"
        assert state.stage == IPEStage.EXECUTE_PLAYBOOK
