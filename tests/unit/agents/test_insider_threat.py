"""Tests for shieldops.agents.insider_threat."""

from __future__ import annotations

from shieldops.agents.insider_threat.models import (
    InsiderStage,
    InsiderThreatState,
    RiskCategory,
    ThreatIndicator,
)


class TestEnums:
    def test_insiderstage_collect_user_signals(self):
        assert InsiderStage.COLLECT_USER_SIGNALS == "collect_user_signals"

    def test_insiderstage_build_behavioral_baseline(self):
        assert InsiderStage.BUILD_BEHAVIORAL_BASELINE == "build_behavioral_baseline"

    def test_insiderstage_detect_deviations(self):
        assert InsiderStage.DETECT_DEVIATIONS == "detect_deviations"

    def test_insiderstage_assess_risk(self):
        assert InsiderStage.ASSESS_RISK == "assess_risk"

    def test_threatindicator_data_hoarding(self):
        assert ThreatIndicator.DATA_HOARDING == "data_hoarding"

    def test_threatindicator_off_hours_access(self):
        assert ThreatIndicator.OFF_HOURS_ACCESS == "off_hours_access"

    def test_threatindicator_privilege_abuse(self):
        assert ThreatIndicator.PRIVILEGE_ABUSE == "privilege_abuse"

    def test_threatindicator_resignation_risk(self):
        assert ThreatIndicator.RESIGNATION_RISK == "resignation_risk"

    def test_riskcategory_flight_risk(self):
        assert RiskCategory.FLIGHT_RISK == "flight_risk"

    def test_riskcategory_data_theft(self):
        assert RiskCategory.DATA_THEFT == "data_theft"

    def test_riskcategory_sabotage(self):
        assert RiskCategory.SABOTAGE == "sabotage"

    def test_riskcategory_espionage(self):
        assert RiskCategory.ESPIONAGE == "espionage"


class TestModels:
    def test_state_defaults(self):
        s = InsiderThreatState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.insider_threat.graph import (
            create_insider_threat_graph,
        )

        sg = create_insider_threat_graph()
        assert sg.compile() is not None
