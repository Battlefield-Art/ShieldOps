"""Tests for shieldops.agents.adaptive_security."""

from __future__ import annotations

from shieldops.agents.adaptive_security.models import (
    AdaptationStage,
    AdaptiveSecurityState,
    ThreatContext,
    ThresholdType,
)


class TestEnums:
    def test_adaptationstage_baseline(self):
        assert AdaptationStage.BASELINE == "baseline"

    def test_adaptationstage_detect_drift(self):
        assert AdaptationStage.DETECT_DRIFT == "detect_drift"

    def test_adaptationstage_propose_adjustment(self):
        assert AdaptationStage.PROPOSE_ADJUSTMENT == "propose_adjustment"

    def test_adaptationstage_evaluate(self):
        assert AdaptationStage.EVALUATE == "evaluate"

    def test_threatcontext_normal(self):
        assert ThreatContext.NORMAL == "normal"

    def test_threatcontext_elevated(self):
        assert ThreatContext.ELEVATED == "elevated"

    def test_threatcontext_active_attack(self):
        assert ThreatContext.ACTIVE_ATTACK == "active_attack"

    def test_threatcontext_post_incident(self):
        assert ThreatContext.POST_INCIDENT == "post_incident"

    def test_thresholdtype_risk_score(self):
        assert ThresholdType.RISK_SCORE == "risk_score"

    def test_thresholdtype_alert_volume(self):
        assert ThresholdType.ALERT_VOLUME == "alert_volume"

    def test_thresholdtype_anomaly_sensitivity(self):
        assert ThresholdType.ANOMALY_SENSITIVITY == "anomaly_sensitivity"

    def test_thresholdtype_response_urgency(self):
        assert ThresholdType.RESPONSE_URGENCY == "response_urgency"


class TestModels:
    def test_state_defaults(self):
        s = AdaptiveSecurityState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.adaptive_security.graph import (
            create_adaptive_security_graph,
        )

        sg = create_adaptive_security_graph()
        assert sg.compile() is not None
