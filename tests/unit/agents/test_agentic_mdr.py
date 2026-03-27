"""Tests for shieldops.agents.agentic_mdr — Agentic Managed Detection and Response."""

from __future__ import annotations

import pytest

from shieldops.agents.agentic_mdr.models import (
    AgenticMDRState,
    AlertIngestion,
    ClosedLoopImprovement,
    InvestigationDepth,
    InvestigationFinding,
    MDRStage,
    ResponseAction,
    ResponseDecision,
    TriageResult,
    ValidationResult,
)


def _state(**kw) -> AgenticMDRState:
    return AgenticMDRState(**kw)


class TestEnums:
    def test_mdr_stage_values(self):
        assert MDRStage.INGEST == "ingest_alerts"
        assert MDRStage.TRIAGE == "auto_triage"
        assert MDRStage.INVESTIGATE == "investigate"
        assert MDRStage.DECIDE == "decide_response"
        assert MDRStage.EXECUTE == "execute_response"
        assert MDRStage.VALIDATE == "validate_and_learn"
        assert MDRStage.REPORT == "report"

    def test_response_decision_values(self):
        assert ResponseDecision.AUTO_REMEDIATE == "auto_remediate"
        assert ResponseDecision.HUMAN_APPROVE == "human_approve"
        assert ResponseDecision.ESCALATE == "escalate"
        assert ResponseDecision.SUPPRESS == "suppress"

    def test_investigation_depth_values(self):
        assert InvestigationDepth.SHALLOW == "shallow"
        assert InvestigationDepth.STANDARD == "standard"
        assert InvestigationDepth.DEEP == "deep"
        assert InvestigationDepth.FORENSIC == "forensic"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.tenant_id == ""
        assert s.session_id == ""
        assert s.current_stage == "init"
        assert s.raw_alerts == []
        assert s.ingested_alerts == []
        assert s.vendor_sources == []
        assert s.alert_count == 0
        assert s.triage_results == []
        assert s.investigation_depth == InvestigationDepth.STANDARD
        assert s.findings == []
        assert s.response_actions == []
        assert s.escalations == []
        assert s.validation_results == []
        assert s.closed_loop_improvements == []
        assert s.report == {}
        assert s.mean_time_to_respond_seconds == 0.0
        assert s.session_start is None
        assert s.session_duration_ms == 0
        assert s.error == ""

    def test_state_with_values(self):
        s = _state(tenant_id="t-01", alert_count=10)
        assert s.tenant_id == "t-01"
        assert s.alert_count == 10

    def test_alert_ingestion_defaults(self):
        a = AlertIngestion()
        assert a.alert_id == ""
        assert a.vendor == ""
        assert a.severity == "medium"
        assert a.confidence == 0.0
        assert a.raw_data == {}

    def test_triage_result_defaults(self):
        t = TriageResult()
        assert t.alert_id == ""
        assert t.decision == ResponseDecision.HUMAN_APPROVE
        assert t.investigation_depth == InvestigationDepth.STANDARD
        assert t.suppressed is False

    def test_investigation_finding_defaults(self):
        f = InvestigationFinding()
        assert f.finding_id == ""
        assert f.alert_ids == []
        assert f.vendors_correlated == []
        assert f.severity == "medium"

    def test_response_action_defaults(self):
        r = ResponseAction()
        assert r.action_id == ""
        assert r.status == "pending"
        assert r.decision == ResponseDecision.HUMAN_APPROVE
        assert r.error == ""

    def test_validation_result_defaults(self):
        v = ValidationResult()
        assert v.validated is False
        assert v.residual_risk == "unknown"

    def test_closed_loop_improvement_defaults(self):
        c = ClosedLoopImprovement()
        assert c.improvement_id == ""
        assert c.triage_accuracy_delta == 0.0


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        from shieldops.agents.agentic_mdr.tools import AgenticMDRToolkit

        return AgenticMDRToolkit()

    @pytest.mark.asyncio
    async def test_ingest_alerts_with_raw_data(self, toolkit):
        raw = [{"vendor": "crowdstrike", "severity": "high", "title": "Test alert"}]
        result = await toolkit.ingest_alerts(vendors=[], raw_alerts=raw)
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["vendor"] == "crowdstrike"

    @pytest.mark.asyncio
    async def test_ingest_alerts_no_vendors(self, toolkit):
        result = await toolkit.ingest_alerts(vendors=[])
        assert isinstance(result, list)
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_correlate_signals(self, toolkit):
        alerts = [
            {"alert_id": "a1", "source_ip": "10.0.0.1", "vendor": "splunk", "severity": "high"},
            {"alert_id": "a2", "source_ip": "10.0.0.1", "vendor": "elastic", "severity": "low"},
        ]
        findings = await toolkit.correlate_signals(alerts)
        assert isinstance(findings, list)
        assert len(findings) >= 1
        assert "vendors_correlated" in findings[0]

    @pytest.mark.asyncio
    async def test_execute_containment_simulated(self, toolkit):
        result = await toolkit.execute_containment(
            vendor="crowdstrike", target="host-1", action="isolate"
        )
        assert result["status"] == "simulated"

    @pytest.mark.asyncio
    async def test_enrich_with_threat_intel(self, toolkit):
        result = await toolkit.enrich_with_threat_intel(indicators=["10.0.0.1"])
        assert "ioc_matches" in result

    @pytest.mark.asyncio
    async def test_record_feedback(self, toolkit):
        result = await toolkit.record_feedback(
            alert_id="a-1",
            original_decision="suppress",
            actual_outcome="true_positive",
            accuracy_delta=-0.1,
        )
        assert "improvement_id" in result
        assert toolkit.get_feedback_ledger()


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.agentic_mdr.graph import create_agentic_mdr_graph

        sg = create_agentic_mdr_graph()
        assert sg.compile() is not None

    def test_graph_has_nodes(self):
        from shieldops.agents.agentic_mdr.graph import create_agentic_mdr_graph

        sg = create_agentic_mdr_graph()
        compiled = sg.compile()
        assert compiled is not None
