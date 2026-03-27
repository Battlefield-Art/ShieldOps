"""Tests for shieldops.agents.cross_vendor_correlator — multi-vendor alert correlation."""

from __future__ import annotations

import pytest

from shieldops.agents.cross_vendor_correlator.models import (
    CorrelationConfidence,
    CorrelationStage,
    CrossVendorCorrelatorState,
    EntityCorrelation,
    KillChainMapping,
    OCSFEvent,
    ReasoningStep,
    Situation,
    VendorAlert,
    VendorSource,
)


def _state(**kw) -> CrossVendorCorrelatorState:
    return CrossVendorCorrelatorState(**kw)


class TestEnums:
    def test_correlation_stage_values(self):
        assert CorrelationStage.INGEST_VENDOR_ALERTS == "ingest_vendor_alerts"
        assert CorrelationStage.NORMALIZE_TO_OCSF == "normalize_to_ocsf"
        assert CorrelationStage.CORRELATE_BY_ENTITY == "correlate_by_entity"
        assert CorrelationStage.BUILD_KILL_CHAIN == "build_kill_chain"
        assert CorrelationStage.CREATE_SITUATIONS == "create_situations"
        assert CorrelationStage.REPORT == "report"

    def test_vendor_source_values(self):
        assert VendorSource.CROWDSTRIKE == "crowdstrike"
        assert VendorSource.DEFENDER == "defender"
        assert VendorSource.WIZ == "wiz"
        assert VendorSource.SPLUNK == "splunk"
        assert VendorSource.ELASTIC == "elastic"
        assert VendorSource.OKTA == "okta"
        assert VendorSource.CLOUDTRAIL == "cloudtrail"
        assert VendorSource.SENTINEL == "sentinel"

    def test_correlation_confidence_values(self):
        assert CorrelationConfidence.STRONG == "strong"
        assert CorrelationConfidence.MODERATE == "moderate"
        assert CorrelationConfidence.WEAK == "weak"
        assert CorrelationConfidence.NONE == "none"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.tenant_id == ""
        assert s.vendors == []
        assert s.time_window_minutes == 60
        assert s.vendor_alerts == []
        assert s.ocsf_events == []
        assert s.correlations == []
        assert s.kill_chain_mappings == []
        assert s.situations == []
        assert s.total_alerts_ingested == 0
        assert s.total_situations_created == 0
        assert s.vendors_correlated == 0
        assert s.current_stage == CorrelationStage.INGEST_VENDOR_ALERTS
        assert s.reasoning_chain == []
        assert s.error == ""
        assert s.session_duration_ms == 0

    def test_vendor_alert_defaults(self):
        va = VendorAlert()
        assert va.id == ""
        assert va.vendor == ""
        assert va.severity == ""
        assert va.entities == []
        assert va.raw_data == {}

    def test_ocsf_event_defaults(self):
        e = OCSFEvent()
        assert e.id == ""
        assert e.category_uid == 0
        assert e.class_uid == 0
        assert e.observables == []
        assert e.raw_data == {}

    def test_entity_correlation_defaults(self):
        ec = EntityCorrelation()
        assert ec.id == ""
        assert ec.entity == ""
        assert ec.confidence == CorrelationConfidence.NONE
        assert ec.event_ids == []
        assert ec.vendors_involved == []

    def test_kill_chain_mapping_defaults(self):
        kc = KillChainMapping()
        assert kc.id == ""
        assert kc.tactic == ""
        assert kc.technique_id == ""
        assert kc.progression_score == 0.0

    def test_situation_defaults(self):
        sit = Situation()
        assert sit.id == ""
        assert sit.title == ""
        assert sit.confidence == CorrelationConfidence.NONE
        assert sit.kill_chain_stages == []
        assert sit.recommended_actions == []

    def test_reasoning_step_defaults(self):
        r = ReasoningStep()
        assert r.step_number == 0
        assert r.action == ""
        assert r.tool_used is None


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        from shieldops.agents.cross_vendor_correlator.tools import (
            CrossVendorCorrelatorToolkit,
        )

        return CrossVendorCorrelatorToolkit()

    @pytest.mark.asyncio
    async def test_ingest_from_vendor(self, toolkit):
        result = await toolkit.ingest_from_vendor(
            tenant_id="t-01", vendors=["crowdstrike", "defender"]
        )
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_normalize_to_ocsf(self, toolkit):
        alerts = [VendorAlert(id="a-1", vendor="crowdstrike", severity="high")]
        result = await toolkit.normalize_to_ocsf(alerts)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_correlate_by_entity(self, toolkit):
        events = [
            OCSFEvent(id="e-1", actor_user="admin", vendor_name="crowdstrike"),
            OCSFEvent(id="e-2", actor_user="admin", vendor_name="defender"),
        ]
        result = await toolkit.correlate_by_entity(events)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_map_kill_chain(self, toolkit):
        corrs = [EntityCorrelation(id="c-1", entity="admin", event_ids=["e-1"])]
        events = [OCSFEvent(id="e-1")]
        result = await toolkit.map_kill_chain(corrs, events)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_create_situation(self, toolkit):
        corrs = [EntityCorrelation(id="c-1", entity="admin")]
        kc = [KillChainMapping(id="kc-1", correlation_id="c-1", tactic="lateral_movement")]
        result = await toolkit.create_situation(corrs, kc)
        assert isinstance(result, list)


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.cross_vendor_correlator.graph import (
            create_cross_vendor_correlator_graph,
        )

        sg = create_cross_vendor_correlator_graph()
        assert sg.compile() is not None

    def test_graph_has_nodes(self):
        from shieldops.agents.cross_vendor_correlator.graph import (
            create_cross_vendor_correlator_graph,
        )

        sg = create_cross_vendor_correlator_graph()
        compiled = sg.compile()
        assert compiled is not None
