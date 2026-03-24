"""Tests for the IdentityRiskEngine.

Covers: risk signal recording, composite risk calculation,
anomalous access detection, action recommendations,
reporting, stats, and clear.
"""

from __future__ import annotations

import pytest

from shieldops.security.identity_risk_engine import (
    IdentityRiskEngine,
    RiskAction,
    RiskFactor,
)


@pytest.fixture()
def engine() -> IdentityRiskEngine:
    return IdentityRiskEngine(max_records=100, high_risk_threshold=60.0)


class TestAddRiskSignal:
    def test_add_risk_signal(self, engine: IdentityRiskEngine) -> None:
        signal = engine.add_risk_signal(
            identity_id="user-1",
            risk_factor=RiskFactor.NO_MFA,
            severity=80.0,
            evidence="No MFA enrolled",
            source="okta",
        )
        assert signal.identity_id == "user-1"
        assert signal.risk_factor == RiskFactor.NO_MFA
        assert signal.severity == 80.0
        stats = engine.get_stats()
        assert stats["total_signals"] == 1

    def test_add_multiple_signals(self, engine: IdentityRiskEngine) -> None:
        engine.add_risk_signal(identity_id="u1", risk_factor=RiskFactor.NO_MFA, severity=50.0)
        engine.add_risk_signal(
            identity_id="u1", risk_factor=RiskFactor.STALE_CREDENTIALS, severity=70.0
        )
        assert engine.get_stats()["total_signals"] == 2


class TestCalculateCompositeRisk:
    def test_calculate_composite_risk(self, engine: IdentityRiskEngine) -> None:
        engine.add_risk_signal(identity_id="u1", risk_factor=RiskFactor.NO_MFA, severity=100.0)
        record = engine.calculate_composite_risk("u1")
        # NO_MFA weight=25.0, severity 100/100=1.0 -> score=25.0
        assert record.composite_risk_score == 25.0
        assert RiskFactor.NO_MFA in record.risk_factors

    def test_calculate_composite_risk_multiple_factors(self, engine: IdentityRiskEngine) -> None:
        engine.add_risk_signal(identity_id="u1", risk_factor=RiskFactor.NO_MFA, severity=100.0)
        engine.add_risk_signal(
            identity_id="u1", risk_factor=RiskFactor.LATERAL_MOVEMENT, severity=100.0
        )
        record = engine.calculate_composite_risk("u1")
        # 25 + 40 = 65
        assert record.composite_risk_score == 65.0
        assert record.recommended_action == RiskAction.REVOKE

    def test_calculate_composite_risk_no_signals(self, engine: IdentityRiskEngine) -> None:
        record = engine.calculate_composite_risk("unknown-user")
        assert record.composite_risk_score == 0.0
        assert record.recommended_action == RiskAction.MONITOR

    def test_risk_capped_at_100(self, engine: IdentityRiskEngine) -> None:
        for factor in RiskFactor:
            engine.add_risk_signal(identity_id="u1", risk_factor=factor, severity=100.0)
        record = engine.calculate_composite_risk("u1")
        assert record.composite_risk_score <= 100.0


class TestDetectAnomalousAccess:
    def test_detect_anomalous_access(self, engine: IdentityRiskEngine) -> None:
        engine.add_risk_signal(
            identity_id="u1",
            risk_factor=RiskFactor.IMPOSSIBLE_TRAVEL,
            severity=90.0,
            evidence="Login from US then China in 10m",
        )
        anomalies = engine.detect_anomalous_access()
        assert len(anomalies) == 1
        assert anomalies[0]["identity_id"] == "u1"
        assert anomalies[0]["max_severity"] == 90.0

    def test_detect_anomalous_access_empty(self, engine: IdentityRiskEngine) -> None:
        engine.add_risk_signal(
            identity_id="u1", risk_factor=RiskFactor.STALE_CREDENTIALS, severity=50.0
        )
        anomalies = engine.detect_anomalous_access()
        assert anomalies == []

    def test_detect_lateral_movement(self, engine: IdentityRiskEngine) -> None:
        engine.add_risk_signal(
            identity_id="u2", risk_factor=RiskFactor.LATERAL_MOVEMENT, severity=85.0
        )
        anomalies = engine.detect_anomalous_access()
        assert len(anomalies) == 1
        assert "lateral_movement" in anomalies[0]["factors"]


class TestRecommendActions:
    def test_recommend_actions(self, engine: IdentityRiskEngine) -> None:
        engine.add_risk_signal(identity_id="u1", risk_factor=RiskFactor.NO_MFA, severity=100.0)
        engine.add_risk_signal(
            identity_id="u1", risk_factor=RiskFactor.PRIVILEGE_ESCALATION, severity=100.0
        )
        engine.calculate_composite_risk("u1")
        recs = engine.recommend_actions()
        assert len(recs) >= 1
        assert recs[0]["identity_id"] == "u1"
        assert recs[0]["recommended_action"] != "monitor"

    def test_recommend_actions_low_risk(self, engine: IdentityRiskEngine) -> None:
        engine.add_risk_signal(
            identity_id="u1", risk_factor=RiskFactor.STALE_CREDENTIALS, severity=10.0
        )
        engine.calculate_composite_risk("u1")
        recs = engine.recommend_actions()
        # Score = 10 * 10/100 = 1.0 -> MONITOR, so no recommendations
        assert recs == []


class TestGenerateReport:
    def test_generate_report(self, engine: IdentityRiskEngine) -> None:
        engine.add_risk_signal(identity_id="u1", risk_factor=RiskFactor.NO_MFA, severity=100.0)
        engine.add_risk_signal(
            identity_id="u2", risk_factor=RiskFactor.IMPOSSIBLE_TRAVEL, severity=90.0
        )
        engine.calculate_composite_risk("u1")
        engine.calculate_composite_risk("u2")
        report = engine.generate_risk_report()
        assert report.total_identities == 2
        assert report.total_signals == 2
        assert len(report.recommendations) >= 1

    def test_generate_report_empty(self, engine: IdentityRiskEngine) -> None:
        report = engine.generate_risk_report()
        assert report.total_identities == 0
        assert report.total_signals == 0
        assert "meets targets" in report.recommendations[0].lower()


class TestGetStats:
    def test_get_stats(self, engine: IdentityRiskEngine) -> None:
        engine.add_risk_signal(identity_id="u1", risk_factor=RiskFactor.NO_MFA, severity=50.0)
        engine.add_risk_signal(identity_id="u2", risk_factor=RiskFactor.NO_MFA, severity=60.0)
        stats = engine.get_stats()
        assert stats["total_signals"] == 2
        assert stats["unique_identities"] == 2
        assert stats["risk_factor_distribution"]["no_mfa"] == 2

    def test_get_stats_empty(self, engine: IdentityRiskEngine) -> None:
        stats = engine.get_stats()
        assert stats["total_signals"] == 0
        assert stats["unique_identities"] == 0


class TestClearData:
    def test_clear_data(self, engine: IdentityRiskEngine) -> None:
        engine.add_risk_signal(identity_id="u1", risk_factor=RiskFactor.NO_MFA, severity=50.0)
        engine.calculate_composite_risk("u1")
        result = engine.clear_data()
        assert result["status"] == "cleared"
        stats = engine.get_stats()
        assert stats["total_records"] == 0
        assert stats["total_signals"] == 0
