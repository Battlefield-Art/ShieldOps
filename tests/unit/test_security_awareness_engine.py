"""Unit tests for security_awareness_engine agent models."""

from __future__ import annotations

from shieldops.agents.security_awareness_engine.models import (
    RiskTier,
    SAEStage,
    SecurityAwarenessEngineState,
    TrainingModule,
)


class TestEnums:
    def test_sae_stage_values(self) -> None:
        assert SAEStage.ASSESS_BASELINE == "assess_baseline"
        assert SAEStage.ANALYZE_PHISHING == "analyze_phishing"
        assert SAEStage.REPORT == "report"

    def test_risk_tier_values(self) -> None:
        assert RiskTier.CRITICAL_RISK == "critical_risk"
        assert RiskTier.HIGH_RISK == "high_risk"
        assert RiskTier.MINIMAL_RISK == "minimal_risk"

    def test_training_module_values(self) -> None:
        assert TrainingModule.PHISHING == "phishing"
        assert TrainingModule.SOCIAL_ENGINEERING == "social_engineering"
        assert TrainingModule.COMPLIANCE == "compliance"


class TestState:
    def test_default_state(self) -> None:
        state = SecurityAwarenessEngineState()
        assert state.request_id == ""
        assert state.stage == SAEStage.ASSESS_BASELINE
        assert state.error == ""

    def test_state_with_values(self) -> None:
        state = SecurityAwarenessEngineState(
            request_id="req-001",
            tenant_id="t-001",
            stage=SAEStage.ANALYZE_PHISHING,
        )
        assert state.request_id == "req-001"
        assert state.stage == SAEStage.ANALYZE_PHISHING
