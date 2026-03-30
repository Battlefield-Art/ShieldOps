"""Tests for privacy_consent_manager."""

from __future__ import annotations

from shieldops.agents.privacy_consent_manager.models import (
    ConsentStatus,
    ConsentType,
    PCMStage,
    PrivacyConsentManagerState,
)


class TestEnums:
    def test_stage(self) -> None:
        assert PCMStage.DISCOVER_CONSENTS == "discover_consents"
        assert len(PCMStage) >= 3

    def test_consent_type(self) -> None:
        assert ConsentType.MARKETING == "marketing"
        assert len(ConsentType) >= 3

    def test_consent_status(self) -> None:
        assert ConsentStatus.ACTIVE == "active"
        assert len(ConsentStatus) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = PrivacyConsentManagerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = PrivacyConsentManagerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
