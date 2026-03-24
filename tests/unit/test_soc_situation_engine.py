"""Tests for the SOCSituationEngine.

Covers: situation creation, action recommendations, status updates,
metrics calculation, reporting, stats, and clear.
"""

from __future__ import annotations

from typing import Any

import pytest

from shieldops.security.soc_situation_engine import (
    ActionType,
    SituationSeverity,
    SituationStatus,
    SOCSituationEngine,
)


@pytest.fixture()
def engine() -> SOCSituationEngine:
    return SOCSituationEngine(max_records=100)


def _make_findings(
    count: int = 2,
    vendor: str = "crowdstrike",
    severity: str = "high",
) -> list[dict[str, Any]]:
    return [
        {
            "id": f"finding-{i}",
            "entity_id": f"entity-{i}",
            "vendor": vendor,
            "severity": severity,
            "mitre_techniques": ["T1059"],
        }
        for i in range(count)
    ]


class TestCreateSituation:
    def test_create_situation(self, engine: SOCSituationEngine) -> None:
        findings = _make_findings(2, vendor="crowdstrike")
        sit = engine.create_situation(
            title="Suspicious process execution",
            findings=findings,
            severity=SituationSeverity.HIGH,
        )
        assert sit.title == "Suspicious process execution"
        assert sit.severity == SituationSeverity.HIGH
        assert sit.status == SituationStatus.NEW
        assert len(sit.finding_ids) == 2
        assert sit.risk_score > 0.0
        assert engine.get_situation(sit.id) is not None

    def test_create_situation_empty_findings(self, engine: SOCSituationEngine) -> None:
        sit = engine.create_situation(title="Manual alert", findings=[])
        assert sit.risk_score == 0.0
        assert sit.finding_ids == []

    def test_create_situation_multi_vendor(self, engine: SOCSituationEngine) -> None:
        findings = _make_findings(1, vendor="crowdstrike") + _make_findings(
            1, vendor="microsoft_defender"
        )
        sit = engine.create_situation(title="Cross-vendor", findings=findings)
        assert len(sit.vendors) == 2
        # Multi-vendor multiplier should increase risk
        assert sit.risk_score > 0.0


class TestRecommendActions:
    def test_recommend_actions_high(self, engine: SOCSituationEngine) -> None:
        findings = _make_findings(2, severity="high")
        sit = engine.create_situation(
            title="High sev", findings=findings, severity=SituationSeverity.HIGH
        )
        actions = engine.recommend_actions(sit.id)
        action_types = {a.action_type for a in actions}
        assert ActionType.INVESTIGATE in action_types
        assert ActionType.CONTAIN in action_types

    def test_recommend_actions_low(self, engine: SOCSituationEngine) -> None:
        findings = _make_findings(1, severity="low")
        sit = engine.create_situation(
            title="Low sev", findings=findings, severity=SituationSeverity.LOW
        )
        actions = engine.recommend_actions(sit.id)
        action_types = {a.action_type for a in actions}
        assert ActionType.MONITOR in action_types

    def test_recommend_actions_critical(self, engine: SOCSituationEngine) -> None:
        findings = _make_findings(3, severity="critical")
        sit = engine.create_situation(
            title="Critical", findings=findings, severity=SituationSeverity.CRITICAL
        )
        actions = engine.recommend_actions(sit.id)
        action_types = {a.action_type for a in actions}
        assert ActionType.ESCALATE in action_types

    def test_recommend_actions_not_found(self, engine: SOCSituationEngine) -> None:
        actions = engine.recommend_actions("nonexistent")
        assert actions == []


class TestUpdateStatus:
    def test_update_status(self, engine: SOCSituationEngine) -> None:
        sit = engine.create_situation(title="Test", findings=_make_findings(1))
        updated = engine.update_status(sit.id, SituationStatus.TRIAGING)
        assert updated is not None
        assert updated.status == SituationStatus.TRIAGING

    def test_update_status_invalid_transition(self, engine: SOCSituationEngine) -> None:
        sit = engine.create_situation(title="Test", findings=_make_findings(1))
        # NEW -> CLOSED is not a valid transition
        result = engine.update_status(sit.id, SituationStatus.CLOSED)
        assert result is None

    def test_update_status_not_found(self, engine: SOCSituationEngine) -> None:
        result = engine.update_status("nonexistent", SituationStatus.TRIAGING)
        assert result is None


class TestCalculateMetrics:
    def test_calculate_metrics(self, engine: SOCSituationEngine) -> None:
        sit = engine.create_situation(title="Test", findings=_make_findings(1))
        engine.execute_action(sit.id, ActionType.INVESTIGATE)
        engine.execute_action(sit.id, ActionType.REMEDIATE)
        metrics = engine.calculate_metrics()
        assert "mttd_seconds" in metrics
        assert "mtta_seconds" in metrics
        assert "mttr_seconds" in metrics

    def test_calculate_metrics_empty(self, engine: SOCSituationEngine) -> None:
        metrics = engine.calculate_metrics()
        assert metrics["mttd_seconds"] == 0.0
        assert metrics["mtta_seconds"] == 0.0
        assert metrics["mttr_seconds"] == 0.0


class TestGenerateReport:
    def test_generate_report(self, engine: SOCSituationEngine) -> None:
        engine.create_situation(
            title="S1", findings=_make_findings(2), severity=SituationSeverity.HIGH
        )
        engine.create_situation(
            title="S2", findings=_make_findings(1), severity=SituationSeverity.LOW
        )
        report = engine.generate_report()
        assert report.total_situations == 2
        assert report.by_severity.get("high", 0) == 1
        assert report.by_severity.get("low", 0) == 1
        assert len(report.recommendations) >= 1

    def test_generate_report_empty(self, engine: SOCSituationEngine) -> None:
        report = engine.generate_report()
        assert report.total_situations == 0
        assert report.avg_risk_score == 0.0
        assert "healthy" in report.recommendations[0].lower()


class TestGetStats:
    def test_get_stats(self, engine: SOCSituationEngine) -> None:
        engine.create_situation(title="S1", findings=_make_findings(1))
        stats = engine.get_stats()
        assert stats["total_situations"] == 1
        assert "status_distribution" in stats
        assert stats["status_distribution"].get("new", 0) == 1

    def test_get_stats_empty(self, engine: SOCSituationEngine) -> None:
        stats = engine.get_stats()
        assert stats["total_situations"] == 0


class TestClearData:
    def test_clear_data(self, engine: SOCSituationEngine) -> None:
        engine.create_situation(title="S1", findings=_make_findings(1))
        engine.create_situation(title="S2", findings=_make_findings(1))
        result = engine.clear_data()
        assert result["status"] == "cleared"
        assert engine.get_stats()["total_situations"] == 0
