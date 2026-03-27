"""Tests for shieldops.agents.detection_engineering."""

from __future__ import annotations

from shieldops.agents.detection_engineering.models import (
    DetectionEngineeringState,
    DetectionStage,
    RuleStatus,
    RuleType,
)


class TestEnums:
    def test_detectionstage_assess_coverage(self):
        assert DetectionStage.ASSESS_COVERAGE == "assess_coverage"

    def test_detectionstage_create_rules(self):
        assert DetectionStage.CREATE_RULES == "create_rules"

    def test_detectionstage_test_rules(self):
        assert DetectionStage.TEST_RULES == "test_rules"

    def test_detectionstage_tune(self):
        assert DetectionStage.TUNE == "tune"

    def test_ruletype_correlation(self):
        assert RuleType.CORRELATION == "correlation"

    def test_ruletype_threshold(self):
        assert RuleType.THRESHOLD == "threshold"

    def test_ruletype_anomaly(self):
        assert RuleType.ANOMALY == "anomaly"

    def test_ruletype_sequence(self):
        assert RuleType.SEQUENCE == "sequence"

    def test_rulestatus_draft(self):
        assert RuleStatus.DRAFT == "draft"

    def test_rulestatus_testing(self):
        assert RuleStatus.TESTING == "testing"

    def test_rulestatus_active(self):
        assert RuleStatus.ACTIVE == "active"

    def test_rulestatus_tuning(self):
        assert RuleStatus.TUNING == "tuning"


class TestModels:
    def test_state_defaults(self):
        s = DetectionEngineeringState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.detection_engineering.graph import (
            create_detection_engineering_graph,
        )

        sg = create_detection_engineering_graph()
        assert sg.compile() is not None
