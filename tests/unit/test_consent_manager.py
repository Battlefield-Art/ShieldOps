"""Tests for consent_manager."""

from __future__ import annotations

from shieldops.agents.consent_manager.models import (
    ConsentManagerState,
    ConsentStage,
    ConsentStatus,
    ConsentType,
)


class TestEnums:
    def test_consentstage(self) -> None:
        assert ConsentStage.COLLECT_CONSENTS == "collect_consents"
        assert len(ConsentStage) >= 3

    def test_consentstatus(self) -> None:
        assert ConsentStatus.ACTIVE == "active"
        assert len(ConsentStatus) >= 3

    def test_consenttype(self) -> None:
        assert ConsentType.EXPLICIT == "explicit"
        assert len(ConsentType) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = ConsentManagerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = ConsentManagerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
