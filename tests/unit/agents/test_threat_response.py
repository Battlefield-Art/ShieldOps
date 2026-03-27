"""Tests for shieldops.agents.threat_response."""

from __future__ import annotations

from shieldops.agents.threat_response.models import (
    ActionStatus,
    ResponseStage,
    ThreatResponseState,
    ThreatSeverity,
)


class TestEnums:
    def test_responsestage_classify_threat(self):
        assert ResponseStage.CLASSIFY_THREAT == "classify_threat"

    def test_responsestage_select_playbook(self):
        assert ResponseStage.SELECT_PLAYBOOK == "select_playbook"

    def test_responsestage_execute_containment(self):
        assert ResponseStage.EXECUTE_CONTAINMENT == "execute_containment"

    def test_responsestage_execute_eradication(self):
        assert ResponseStage.EXECUTE_ERADICATION == "execute_eradication"

    def test_threatseverity_critical(self):
        assert ThreatSeverity.CRITICAL == "critical"

    def test_threatseverity_high(self):
        assert ThreatSeverity.HIGH == "high"

    def test_threatseverity_medium(self):
        assert ThreatSeverity.MEDIUM == "medium"

    def test_threatseverity_low(self):
        assert ThreatSeverity.LOW == "low"

    def test_actionstatus_pending(self):
        assert ActionStatus.PENDING == "pending"

    def test_actionstatus_in_progress(self):
        assert ActionStatus.IN_PROGRESS == "in_progress"

    def test_actionstatus_completed(self):
        assert ActionStatus.COMPLETED == "completed"

    def test_actionstatus_failed(self):
        assert ActionStatus.FAILED == "failed"


class TestModels:
    def test_state_defaults(self):
        s = ThreatResponseState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.threat_response.graph import (
            create_threat_response_graph,
        )

        sg = create_threat_response_graph()
        assert sg.compile() is not None
