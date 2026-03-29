"""Tests for phishing_email_analyzer."""

from __future__ import annotations

from shieldops.agents.phishing_email_analyzer.models import (
    PhishingEmailAnalyzerState,
    PhishingIndicator,
    PhishingStage,
    RiskLevel,
)


class TestEnums:
    def test_phishingindicator(self) -> None:
        assert PhishingIndicator.SPOOFED_SENDER == "spoofed_sender"
        assert len(PhishingIndicator) >= 3

    def test_phishingstage(self) -> None:
        assert PhishingStage.INGEST_EMAIL == "ingest_email"
        assert len(PhishingStage) >= 3

    def test_risklevel(self) -> None:
        assert RiskLevel.CRITICAL == "critical"
        assert len(RiskLevel) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = PhishingEmailAnalyzerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = PhishingEmailAnalyzerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
