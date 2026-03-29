"""Tests for ticket_automation."""

from __future__ import annotations

from shieldops.agents.ticket_automation.models import (
    AutomationStage,
    SLAStatus,
    TicketAutomationState,
)


class TestEnums:
    def test_automationstage(self) -> None:
        assert AutomationStage.CLASSIFY_EVENT == "classify_event"
        assert len(AutomationStage) >= 3

    def test_slastatus(self) -> None:
        assert SLAStatus.WITHIN_SLA == "within_sla"
        assert len(SLAStatus) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = TicketAutomationState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = TicketAutomationState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
