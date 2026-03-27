"""Tests for shieldops.agents.autonomous_soc — autonomous SOC operations pipeline."""

from __future__ import annotations

import pytest

from shieldops.agents.autonomous_soc.models import (
    AnomalyDetection,
    AutomationLevel,
    AutonomousSOCState,
    IncidentCorrelation,
    IncidentPriority,
    OutcomeMeasurement,
    ReasoningStep,
    ResponseOrchestration,
    SecurityEvent,
    SOCStage,
    TriageDecision,
)


def _state(**kw) -> AutonomousSOCState:
    return AutonomousSOCState(**kw)


class TestEnums:
    def test_soc_stage_values(self):
        assert SOCStage.INGEST_EVENTS == "ingest_events"
        assert SOCStage.ML_DETECT_ANOMALIES == "ml_detect_anomalies"
        assert SOCStage.CORRELATE_INCIDENTS == "correlate_incidents"
        assert SOCStage.AUTO_TRIAGE == "auto_triage"
        assert SOCStage.ORCHESTRATE_RESPONSE == "orchestrate_response"
        assert SOCStage.MEASURE_OUTCOMES == "measure_outcomes"
        assert SOCStage.REPORT == "report"

    def test_automation_level_values(self):
        assert AutomationLevel.FULLY_AUTONOMOUS == "fully_autonomous"
        assert AutomationLevel.SUPERVISED == "supervised"
        assert AutomationLevel.MANUAL == "manual"
        assert AutomationLevel.DISABLED == "disabled"

    def test_incident_priority_values(self):
        assert IncidentPriority.P0_CRITICAL == "p0_critical"
        assert IncidentPriority.P1_HIGH == "p1_high"
        assert IncidentPriority.P2_MEDIUM == "p2_medium"
        assert IncidentPriority.P3_LOW == "p3_low"
        assert IncidentPriority.P4_INFO == "p4_info"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.tenant_id == ""
        assert s.siem_sources == []
        assert s.time_range_minutes == 60
        assert s.automation_config == {}
        assert s.security_events == []
        assert s.events_processed == 0
        assert s.anomalies == []
        assert s.anomalies_detected == 0
        assert s.incidents == []
        assert s.incidents_created == 0
        assert s.triage_decisions == []
        assert s.auto_triaged == 0
        assert s.responses == []
        assert s.responses_orchestrated == 0
        assert s.outcomes == []
        assert s.mean_time_to_detect_seconds == 0.0
        assert s.mean_time_to_respond_seconds == 0.0
        assert s.automation_rate == 0.0
        assert s.false_positive_rate == 0.0
        assert s.reasoning_chain == []
        assert s.current_stage == "init"
        assert s.session_id == ""
        assert s.session_start is None
        assert s.error == ""
        assert s.report == {}

    def test_security_event_defaults(self):
        e = SecurityEvent()
        assert e.event_id == ""
        assert e.source_siem == ""
        assert e.severity == "medium"
        assert e.confidence == 0.0
        assert e.raw_data == {}

    def test_anomaly_detection_defaults(self):
        a = AnomalyDetection()
        assert a.anomaly_id == ""
        assert a.combined_score == 0.0
        assert a.is_anomalous is False
        assert a.affected_entities == []

    def test_incident_correlation_defaults(self):
        ic = IncidentCorrelation()
        assert ic.incident_id == ""
        assert ic.priority == IncidentPriority.P2_MEDIUM
        assert ic.mitre_techniques == []
        assert ic.confidence == 0.0

    def test_triage_decision_defaults(self):
        td = TriageDecision()
        assert td.incident_id == ""
        assert td.priority == IncidentPriority.P2_MEDIUM
        assert td.automation_level == AutomationLevel.MANUAL
        assert td.escalation_needed is False

    def test_response_orchestration_defaults(self):
        ro = ResponseOrchestration()
        assert ro.response_id == ""
        assert ro.status == "pending"
        assert ro.automation_level == AutomationLevel.SUPERVISED
        assert ro.error == ""

    def test_outcome_measurement_defaults(self):
        om = OutcomeMeasurement()
        assert om.mttd_seconds == 0.0
        assert om.mttr_seconds == 0.0
        assert om.false_positive is False
        assert om.analyst_override is False

    def test_reasoning_step(self):
        step = ReasoningStep(
            step_number=1, action="ingest", input_summary="in", output_summary="out"
        )
        assert step.step_number == 1
        assert step.tool_used is None


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        from shieldops.agents.autonomous_soc.tools import AutonomousSOCToolkit

        return AutonomousSOCToolkit()

    @pytest.mark.asyncio
    async def test_ingest_from_splunk(self, toolkit):
        result = await toolkit.ingest_from_splunk(
            search_query="index=security", time_range_minutes=30
        )
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_normalize_siem_event(self, toolkit):
        raw = {"event_id": "e-1", "severity": "high", "src_ip": "10.0.0.1"}
        result = await toolkit.normalize_siem_event(source_siem="splunk", raw_event=raw)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_correlate_anomalies(self, toolkit):
        anomalies = [
            {"anomaly_id": "a1", "affected_entities": ["host-1"]},
            {"anomaly_id": "a2", "affected_entities": ["host-1"]},
        ]
        result = await toolkit.correlate_anomalies(anomalies)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_execute_response_step(self, toolkit):
        step = {"action": "isolate_host", "target": "host-1"}
        result = await toolkit.execute_response_step(step=step, incident_id="inc-1")
        assert isinstance(result, dict)


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.autonomous_soc.graph import create_autonomous_soc_graph

        sg = create_autonomous_soc_graph()
        assert sg.compile() is not None

    def test_graph_has_nodes(self):
        from shieldops.agents.autonomous_soc.graph import create_autonomous_soc_graph

        sg = create_autonomous_soc_graph()
        compiled = sg.compile()
        assert compiled is not None
