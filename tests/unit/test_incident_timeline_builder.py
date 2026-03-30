"""Unit tests for incident_timeline_builder agent models."""

from __future__ import annotations

from shieldops.agents.incident_timeline_builder.models import (
    EventSeverity,
    EventSource,
    IncidentTimelineBuilderState,
    ITBStage,
)


class TestEnums:
    def test_itb_stage_values(self) -> None:
        assert ITBStage.COLLECT_EVENTS == "collect_events"
        assert ITBStage.BUILD_TIMELINE == "build_timeline"
        assert ITBStage.REPORT == "report"

    def test_event_source(self) -> None:
        assert EventSource.SIEM == "siem"
        assert EventSource.EDR == "edr"
        assert EventSource.CLOUD_TRAIL == "cloud_trail"

    def test_event_severity(self) -> None:
        assert EventSeverity.CRITICAL == "critical"
        assert EventSeverity.INFO == "info"


class TestState:
    def test_default_state(self) -> None:
        state = IncidentTimelineBuilderState()
        assert state.request_id == ""
        assert state.stage == ITBStage.COLLECT_EVENTS
        assert state.error == ""

    def test_state_with_values(self) -> None:
        state = IncidentTimelineBuilderState(
            request_id="req-001",
            stage=ITBStage.BUILD_TIMELINE,
        )
        assert state.stage == ITBStage.BUILD_TIMELINE
