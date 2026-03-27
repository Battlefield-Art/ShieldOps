"""Tests for shieldops.agents.autonomous_xdr — vendor-neutral Extended Detection and Response."""

from __future__ import annotations

import pytest

from shieldops.agents.autonomous_xdr.models import (
    AutonomousXDRState,
    CampaignDetection,
    CampaignSeverity,
    CrossDomainCorrelation,
    InvestigationResult,
    NormalizedAlert,
    ReasoningStep,
    SignalDomain,
    TelemetrySignal,
    XDRStage,
)


def _state(**kw) -> AutonomousXDRState:
    return AutonomousXDRState(**kw)


class TestEnums:
    def test_xdr_stage_values(self):
        assert XDRStage.COLLECT_TELEMETRY == "collect_telemetry"
        assert XDRStage.NORMALIZE_SIGNALS == "normalize_signals"
        assert XDRStage.CORRELATE_CROSS_DOMAIN == "correlate_cross_domain"
        assert XDRStage.DETECT_CAMPAIGNS == "detect_campaigns"
        assert XDRStage.AUTO_INVESTIGATE == "auto_investigate"
        assert XDRStage.RESPOND == "respond"
        assert XDRStage.REPORT == "report"

    def test_signal_domain_values(self):
        assert SignalDomain.ENDPOINT == "endpoint"
        assert SignalDomain.NETWORK == "network"
        assert SignalDomain.CLOUD == "cloud"
        assert SignalDomain.IDENTITY == "identity"
        assert SignalDomain.EMAIL == "email"
        assert SignalDomain.IOT == "iot"

    def test_campaign_severity_values(self):
        assert CampaignSeverity.CRITICAL == "critical"
        assert CampaignSeverity.HIGH == "high"
        assert CampaignSeverity.MEDIUM == "medium"
        assert CampaignSeverity.LOW == "low"
        assert CampaignSeverity.INFO == "info"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.session_id == ""
        assert s.tenant_id == ""
        assert s.stage == XDRStage.COLLECT_TELEMETRY
        assert s.config == {}
        assert s.signals_collected == []
        assert s.normalized_alerts == []
        assert s.correlations_found == []
        assert s.campaigns_detected == []
        assert s.investigations_completed == []
        assert s.auto_responses == []
        assert s.detection_coverage_pct == 0.0
        assert s.domains_covered == []
        assert s.vendors_queried == []
        assert s.reasoning_chain == []
        assert s.current_step == "init"
        assert s.session_start is None
        assert s.session_duration_ms == 0
        assert s.error == ""

    def test_telemetry_signal_defaults(self):
        t = TelemetrySignal()
        assert t.id == ""
        assert t.vendor == ""
        assert t.domain == SignalDomain.ENDPOINT
        assert t.severity == "medium"
        assert t.raw_data == {}

    def test_normalized_alert_defaults(self):
        n = NormalizedAlert()
        assert n.id == ""
        assert n.domain == SignalDomain.ENDPOINT
        assert n.confidence == 0.0
        assert n.entities == []

    def test_cross_domain_correlation_defaults(self):
        c = CrossDomainCorrelation()
        assert c.id == ""
        assert c.alert_ids == []
        assert c.correlation_score == 0.0

    def test_campaign_detection_defaults(self):
        cd = CampaignDetection()
        assert cd.id == ""
        assert cd.severity == CampaignSeverity.MEDIUM
        assert cd.blast_radius == 0
        assert cd.confidence == 0.0

    def test_investigation_result_defaults(self):
        ir = InvestigationResult()
        assert ir.id == ""
        assert ir.root_cause == ""
        assert ir.containment_urgency == "medium"
        assert ir.evidence == []

    def test_reasoning_step_required_fields(self):
        step = ReasoningStep(
            step_number=1, action="collect", input_summary="in", output_summary="out"
        )
        assert step.step_number == 1
        assert step.tool_used is None


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        from shieldops.agents.autonomous_xdr.tools import AutonomousXDRToolkit

        return AutonomousXDRToolkit()

    @pytest.mark.asyncio
    async def test_collect_telemetry(self, toolkit):
        result = await toolkit.collect_telemetry(domains=["endpoint", "network"])
        assert isinstance(result, list)
        assert len(result) > 0

    @pytest.mark.asyncio
    async def test_normalize_to_ocsf(self, toolkit):
        signals = await toolkit.collect_telemetry()
        normalized = await toolkit.normalize_to_ocsf(signals)
        assert isinstance(normalized, list)

    @pytest.mark.asyncio
    async def test_correlate_cross_domain(self, toolkit):
        signals = await toolkit.collect_telemetry()
        normalized = await toolkit.normalize_to_ocsf(signals)
        correlations = await toolkit.correlate_cross_domain(normalized)
        assert isinstance(correlations, list)

    @pytest.mark.asyncio
    async def test_detect_campaigns(self, toolkit):
        signals = await toolkit.collect_telemetry()
        normalized = await toolkit.normalize_to_ocsf(signals)
        correlations = await toolkit.correlate_cross_domain(normalized)
        campaigns = await toolkit.detect_campaigns(correlations, normalized)
        assert isinstance(campaigns, list)


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.autonomous_xdr.graph import create_autonomous_xdr_graph

        sg = create_autonomous_xdr_graph()
        assert sg.compile() is not None

    def test_graph_has_nodes(self):
        from shieldops.agents.autonomous_xdr.graph import create_autonomous_xdr_graph

        sg = create_autonomous_xdr_graph()
        compiled = sg.compile()
        assert compiled is not None
