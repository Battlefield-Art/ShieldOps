"""Unit tests for iam_policy_analyzer agent models."""

from __future__ import annotations

from shieldops.agents.iam_policy_analyzer.models import (
    CloudProvider,
    IAMPolicyAnalyzerState,
    IPAStage,
    RiskLevel,
)


class TestEnums:
    def test_ipa_stage_values(self) -> None:
        assert IPAStage.COLLECT_POLICIES == "collect_policies"
        assert IPAStage.DETECT_OVERPRIVILEGE == "detect_overprivilege"
        assert IPAStage.REPORT == "report"

    def test_cloud_provider_values(self) -> None:
        assert CloudProvider.AWS == "aws"
        assert CloudProvider.GCP == "gcp"
        assert CloudProvider.AZURE == "azure"

    def test_risk_level_values(self) -> None:
        assert RiskLevel.CRITICAL == "critical"
        assert RiskLevel.HIGH == "high"
        assert RiskLevel.LOW == "low"


class TestState:
    def test_default_state(self) -> None:
        state = IAMPolicyAnalyzerState()
        assert state.request_id == ""
        assert state.stage == IPAStage.COLLECT_POLICIES
        assert state.error == ""

    def test_state_with_values(self) -> None:
        state = IAMPolicyAnalyzerState(
            request_id="req-001",
            tenant_id="t-001",
            stage=IPAStage.DETECT_OVERPRIVILEGE,
        )
        assert state.request_id == "req-001"
        assert state.stage == IPAStage.DETECT_OVERPRIVILEGE
