"""Tests for shieldops.agents.data_intelligence."""

from __future__ import annotations

import pytest

from shieldops.agents.data_intelligence.models import (
    AIClassification,
    DataDiscovery,
    DataDomain,
    DataIntelligenceState,
    DataIntelStage,
    DataLineage,
    DataRisk,
    ProtectionPlan,
    ProtectionRecommendation,
    ReasoningStep,
)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestEnums:
    def test_data_intel_stage_values(self) -> None:
        assert DataIntelStage.DISCOVER_DATA == "discover_data"
        assert DataIntelStage.CLASSIFY_WITH_AI == "classify_with_ai"
        assert DataIntelStage.MAP_DATA_LINEAGE == "map_data_lineage"
        assert DataIntelStage.ASSESS_DATA_RISK == "assess_data_risk"
        assert DataIntelStage.RECOMMEND_PROTECTION == "recommend_protection"
        assert DataIntelStage.REPORT == "report"
        assert len(DataIntelStage) == 6

    def test_data_domain_values(self) -> None:
        assert DataDomain.STRUCTURED == "structured"
        assert DataDomain.UNSTRUCTURED == "unstructured"
        assert DataDomain.SEMI_STRUCTURED == "semi_structured"
        assert DataDomain.AI_TRAINING == "ai_training"
        assert DataDomain.EMBEDDING == "embedding"
        assert DataDomain.MODEL_ARTIFACT == "model_artifact"
        assert len(DataDomain) == 6

    def test_protection_recommendation_values(self) -> None:
        assert ProtectionRecommendation.ENCRYPT == "encrypt"
        assert ProtectionRecommendation.MASK == "mask"
        assert ProtectionRecommendation.RESTRICT_ACCESS == "restrict_access"
        assert ProtectionRecommendation.BACKUP == "backup"
        assert ProtectionRecommendation.IMMUTABLE_LOCK == "immutable_lock"
        assert ProtectionRecommendation.DELETE == "delete"
        assert len(ProtectionRecommendation) == 6


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TestModels:
    def test_state_defaults(self) -> None:
        state = DataIntelligenceState()
        assert state.request_id == ""
        assert state.tenant_id == ""
        assert state.stage == DataIntelStage.DISCOVER_DATA
        assert state.discoveries == []
        assert state.classifications == []
        assert state.lineages == []
        assert state.risks == []
        assert state.plans == []
        assert state.report == ""
        assert state.total_sources == 0
        assert state.high_risk_count == 0
        assert state.pii_sources == 0
        assert state.reasoning_chain == []
        assert state.error == ""

    def test_data_discovery_defaults(self) -> None:
        dd = DataDiscovery()
        assert dd.domain == DataDomain.STRUCTURED
        assert dd.size_gb == 0.0
        assert dd.record_count == 0
        assert dd.encrypted is False

    def test_ai_classification_defaults(self) -> None:
        ac = AIClassification()
        assert ac.sensitivity_level == ""
        assert ac.data_types == []
        assert ac.pii_detected is False
        assert ac.phi_detected is False
        assert ac.pci_detected is False
        assert 0.0 <= ac.confidence <= 1.0
        assert ac.regulatory_frameworks == []

    def test_data_lineage_defaults(self) -> None:
        dl = DataLineage()
        assert dl.source_systems == []
        assert dl.downstream_consumers == []
        assert dl.transformations == []
        assert dl.retention_days == 0
        assert dl.cross_border is False

    def test_data_risk_defaults(self) -> None:
        dr = DataRisk()
        assert 0.0 <= dr.risk_score <= 10.0
        assert dr.access_violations == 0
        assert dr.stale_permissions == 0
        assert dr.compliance_gaps == []
        assert dr.threat_vectors == []

    def test_protection_plan_defaults(self) -> None:
        pp = ProtectionPlan()
        assert pp.recommendations == []
        assert pp.estimated_effort_hours == 0.0
        assert pp.rationale == ""

    def test_reasoning_step_defaults(self) -> None:
        step = ReasoningStep()
        assert step.step == ""
        assert step.confidence == 0.0
        assert step.metadata == {}


# ---------------------------------------------------------------------------
# Toolkit
# ---------------------------------------------------------------------------


class TestToolkit:
    @pytest.fixture()
    def toolkit(self):
        from shieldops.agents.data_intelligence.tools import DataIntelligenceToolkit

        return DataIntelligenceToolkit()

    @pytest.mark.asyncio
    async def test_discover_data(self, toolkit) -> None:
        result = await toolkit.discover_data("tenant-1")
        assert isinstance(result, list)
        assert len(result) >= 1
        assert all(isinstance(d, DataDiscovery) for d in result)

    @pytest.mark.asyncio
    async def test_classify_with_ai(self, toolkit) -> None:
        discoveries = [
            DataDiscovery(id="d1", name="customer_db", domain=DataDomain.STRUCTURED),
        ]
        result = await toolkit.classify_with_ai(discoveries)
        assert isinstance(result, list)
        assert len(result) >= 1
        assert all(isinstance(c, AIClassification) for c in result)

    @pytest.mark.asyncio
    async def test_map_lineage(self, toolkit) -> None:
        discoveries = [
            DataDiscovery(id="d1", name="customer_db"),
        ]
        result = await toolkit.map_lineage(discoveries)
        assert isinstance(result, list)
        assert len(result) >= 1
        assert all(isinstance(item, DataLineage) for item in result)

    @pytest.mark.asyncio
    async def test_assess_risk(self, toolkit) -> None:
        discoveries = [DataDiscovery(id="d1", name="customer_db")]
        classifications = [AIClassification(data_id="d1", pii_detected=True)]
        lineages = [DataLineage(data_id="d1", cross_border=True)]
        result = await toolkit.assess_risk(discoveries, classifications, lineages)
        assert isinstance(result, list)
        assert len(result) >= 1
        assert all(isinstance(r, DataRisk) for r in result)

    @pytest.mark.asyncio
    async def test_recommend_protection(self, toolkit) -> None:
        discoveries = [DataDiscovery(id="d1", name="customer_db")]
        risks = [DataRisk(data_id="d1", risk_score=8.0)]
        classifications = [AIClassification(data_id="d1", pii_detected=True)]
        result = await toolkit.recommend_protection(discoveries, risks, classifications)
        assert isinstance(result, list)
        assert len(result) >= 1
        assert all(isinstance(p, ProtectionPlan) for p in result)


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


class TestGraph:
    def test_graph_compiles(self) -> None:
        from shieldops.agents.data_intelligence.graph import build_graph
        from shieldops.agents.data_intelligence.tools import DataIntelligenceToolkit

        toolkit = DataIntelligenceToolkit()
        graph = build_graph(toolkit)
        compiled = graph.compile()
        assert compiled is not None

    def test_create_factory(self) -> None:
        from shieldops.agents.data_intelligence.graph import create_data_intelligence_graph

        graph = create_data_intelligence_graph()
        compiled = graph.compile()
        assert compiled is not None
