"""Tests for the Threat Modeling Agent."""

from __future__ import annotations

import pytest

from shieldops.agents.threat_modeling.models import (
    Mitigation,
    ModelingStage,
    ReasoningStep,
    ServiceComponent,
    StrideCategory,
    ThreatLikelihood,
    ThreatModelingState,
    ThreatVector,
)
from shieldops.agents.threat_modeling.nodes import (
    analyze_threats,
    assess_risk,
    discover_architecture,
    recommend_mitigations,
)
from shieldops.agents.threat_modeling.tools import ThreatModelingToolkit


# ── StrEnum tests ──────────────────────────────────────────────────────


class TestModelingStage:
    def test_values(self) -> None:
        assert ModelingStage.DISCOVER == "discover"
        assert ModelingStage.ANALYZE == "analyze"
        assert ModelingStage.ASSESS == "assess"
        assert ModelingStage.MITIGATE == "mitigate"

    def test_member_count(self) -> None:
        assert len(ModelingStage) == 4


class TestStrideCategory:
    def test_values(self) -> None:
        assert StrideCategory.SPOOFING == "spoofing"
        assert StrideCategory.TAMPERING == "tampering"
        assert StrideCategory.REPUDIATION == "repudiation"
        assert StrideCategory.INFORMATION_DISCLOSURE == "information_disclosure"
        assert StrideCategory.DENIAL_OF_SERVICE == "denial_of_service"
        assert StrideCategory.ELEVATION_OF_PRIVILEGE == "elevation_of_privilege"

    def test_member_count(self) -> None:
        assert len(StrideCategory) == 6


class TestThreatLikelihood:
    def test_values(self) -> None:
        assert ThreatLikelihood.VERY_LIKELY == "very_likely"
        assert ThreatLikelihood.LIKELY == "likely"
        assert ThreatLikelihood.POSSIBLE == "possible"
        assert ThreatLikelihood.UNLIKELY == "unlikely"
        assert ThreatLikelihood.RARE == "rare"

    def test_member_count(self) -> None:
        assert len(ThreatLikelihood) == 5


# ── Pydantic model tests ──────────────────────────────────────────────


class TestServiceComponent:
    def test_defaults(self) -> None:
        c = ServiceComponent()
        assert c.name == ""
        assert c.component_type == ""
        assert c.trust_boundary == ""
        assert c.data_flows == []
        assert c.technologies == []

    def test_custom_values(self) -> None:
        c = ServiceComponent(
            name="api_gateway",
            component_type="api",
            trust_boundary="dmz",
            data_flows=["inbound", "outbound"],
            technologies=["FastAPI"],
        )
        assert c.name == "api_gateway"
        assert len(c.data_flows) == 2
        assert "FastAPI" in c.technologies


class TestThreatVector:
    def test_defaults(self) -> None:
        t = ThreatVector()
        assert t.id == ""
        assert t.stride_category == StrideCategory.SPOOFING
        assert t.impact_score == 0.0
        assert t.risk_score == 0.0

    def test_score_bounds(self) -> None:
        t = ThreatVector(impact_score=50.0, risk_score=75.0)
        assert 0.0 <= t.impact_score <= 100.0
        assert 0.0 <= t.risk_score <= 100.0

    def test_serialization(self) -> None:
        t = ThreatVector(
            id="THR-001",
            stride_category=StrideCategory.TAMPERING,
            component="db",
            description="SQL injection",
            likelihood=ThreatLikelihood.LIKELY,
            impact_score=85.0,
            risk_score=68.0,
            mitre_technique="T1190",
        )
        data = t.model_dump()
        assert data["id"] == "THR-001"
        assert data["stride_category"] == "tampering"
        restored = ThreatVector(**data)
        assert restored.id == t.id


class TestMitigation:
    def test_defaults(self) -> None:
        m = Mitigation()
        assert m.threat_id == ""
        assert m.description == ""
        assert m.control_type == ""

    def test_custom_values(self) -> None:
        m = Mitigation(
            threat_id="THR-001",
            description="Enable encryption",
            control_type="preventive",
            effort="medium",
            effectiveness="high",
        )
        assert m.threat_id == "THR-001"
        assert m.effectiveness == "high"


class TestThreatModelingState:
    def test_defaults(self) -> None:
        s = ThreatModelingState()
        assert s.request_id == ""
        assert s.stage == ModelingStage.DISCOVER
        assert s.target_service == ""
        assert s.components == []
        assert s.threats == []
        assert s.mitigations == []
        assert s.residual_risk == 0.0
        assert s.reasoning_chain == []
        assert s.error == ""

    def test_custom_state(self) -> None:
        s = ThreatModelingState(
            request_id="req-123",
            target_service="payment-service",
            stage=ModelingStage.ANALYZE,
        )
        assert s.request_id == "req-123"
        assert s.target_service == "payment-service"
        assert s.stage == ModelingStage.ANALYZE


class TestReasoningStep:
    def test_defaults(self) -> None:
        r = ReasoningStep()
        assert r.step == ""
        assert r.confidence == 0.0


# ── Toolkit tests ─────────────────────────────────────────────────────


class TestThreatModelingToolkit:
    @pytest.fixture()
    def toolkit(self) -> ThreatModelingToolkit:
        return ThreatModelingToolkit()

    @pytest.mark.asyncio()
    async def test_discover_components_web_app(
        self, toolkit: ThreatModelingToolkit
    ) -> None:
        components = await toolkit.discover_components("web_application")
        assert len(components) > 0
        assert all(isinstance(c, ServiceComponent) for c in components)
        names = [c.name for c in components]
        assert "load_balancer" in names

    @pytest.mark.asyncio()
    async def test_discover_components_microservice(
        self, toolkit: ThreatModelingToolkit
    ) -> None:
        components = await toolkit.discover_components("microservice")
        assert len(components) > 0
        names = [c.name for c in components]
        assert "service_mesh" in names

    @pytest.mark.asyncio()
    async def test_discover_components_default(
        self, toolkit: ThreatModelingToolkit
    ) -> None:
        components = await toolkit.discover_components("unknown_service")
        assert len(components) > 0

    @pytest.mark.asyncio()
    async def test_analyze_threats_produces_vectors(
        self, toolkit: ThreatModelingToolkit
    ) -> None:
        components = await toolkit.discover_components("web_application")
        threats = await toolkit.analyze_threats(components)
        assert len(threats) > 0
        assert all(isinstance(t, ThreatVector) for t in threats)

    @pytest.mark.asyncio()
    async def test_analyze_threats_unique_ids(
        self, toolkit: ThreatModelingToolkit
    ) -> None:
        components = await toolkit.discover_components("web_application")
        threats = await toolkit.analyze_threats(components)
        ids = [t.id for t in threats]
        assert len(ids) == len(set(ids)), "Threat IDs must be unique"

    @pytest.mark.asyncio()
    async def test_analyze_threats_has_mitre_techniques(
        self, toolkit: ThreatModelingToolkit
    ) -> None:
        components = await toolkit.discover_components("web_application")
        threats = await toolkit.analyze_threats(components)
        for t in threats:
            assert t.mitre_technique.startswith("T"), (
                f"MITRE technique should start with T: {t.mitre_technique}"
            )

    @pytest.mark.asyncio()
    async def test_assess_risk_scores_threats(
        self, toolkit: ThreatModelingToolkit
    ) -> None:
        components = await toolkit.discover_components("web_application")
        threats = await toolkit.analyze_threats(components)
        scored = await toolkit.assess_risk(threats)
        assert len(scored) == len(threats)
        for t in scored:
            assert t.risk_score > 0.0

    @pytest.mark.asyncio()
    async def test_assess_risk_sorted_descending(
        self, toolkit: ThreatModelingToolkit
    ) -> None:
        components = await toolkit.discover_components("web_application")
        threats = await toolkit.analyze_threats(components)
        scored = await toolkit.assess_risk(threats)
        scores = [t.risk_score for t in scored]
        assert scores == sorted(scores, reverse=True)

    @pytest.mark.asyncio()
    async def test_recommend_mitigations(
        self, toolkit: ThreatModelingToolkit
    ) -> None:
        components = await toolkit.discover_components("web_application")
        threats = await toolkit.analyze_threats(components)
        scored = await toolkit.assess_risk(threats)
        mitigations = await toolkit.recommend_mitigations(scored)
        assert len(mitigations) > 0
        assert all(isinstance(m, Mitigation) for m in mitigations)

    def test_calculate_residual_risk(
        self, toolkit: ThreatModelingToolkit
    ) -> None:
        threats = [
            ThreatVector(
                id="THR-1", risk_score=80.0,
                stride_category=StrideCategory.TAMPERING,
            ),
            ThreatVector(
                id="THR-2", risk_score=60.0,
                stride_category=StrideCategory.SPOOFING,
            ),
        ]
        mitigations = [
            Mitigation(threat_id="THR-1", effectiveness="high"),
            Mitigation(threat_id="THR-2", effectiveness="medium"),
        ]
        residual = toolkit.calculate_residual_risk(threats, mitigations)
        assert 0.0 <= residual <= 100.0
        # With mitigations applied, residual should be less than average raw risk
        avg_raw = (80.0 + 60.0) / 2
        assert residual < avg_raw

    def test_calculate_residual_risk_no_threats(
        self, toolkit: ThreatModelingToolkit
    ) -> None:
        assert toolkit.calculate_residual_risk([], []) == 0.0

    def test_calculate_residual_risk_no_mitigations(
        self, toolkit: ThreatModelingToolkit
    ) -> None:
        threats = [
            ThreatVector(id="THR-1", risk_score=80.0),
        ]
        residual = toolkit.calculate_residual_risk(threats, [])
        assert residual == 80.0


# ── Node tests ────────────────────────────────────────────────────────


class TestNodes:
    @pytest.fixture()
    def toolkit(self) -> ThreatModelingToolkit:
        return ThreatModelingToolkit()

    @pytest.mark.asyncio()
    async def test_discover_architecture_node(
        self, toolkit: ThreatModelingToolkit
    ) -> None:
        state: dict = {"target_service": "web_app", "reasoning_chain": []}
        result = await discover_architecture(state, toolkit)
        assert result["stage"] == ModelingStage.ANALYZE.value
        assert len(result["components"]) > 0
        assert len(result["reasoning_chain"]) == 1

    @pytest.mark.asyncio()
    async def test_analyze_threats_node(
        self, toolkit: ThreatModelingToolkit
    ) -> None:
        components = await toolkit.discover_components("web_application")
        state: dict = {
            "components": [c.model_dump() for c in components],
            "reasoning_chain": [],
        }
        result = await analyze_threats(state, toolkit)
        assert result["stage"] == ModelingStage.ASSESS.value
        assert len(result["threats"]) > 0

    @pytest.mark.asyncio()
    async def test_assess_risk_node(
        self, toolkit: ThreatModelingToolkit
    ) -> None:
        components = await toolkit.discover_components("web_application")
        threats = await toolkit.analyze_threats(components)
        state: dict = {
            "threats": [t.model_dump() for t in threats],
            "reasoning_chain": [],
        }
        result = await assess_risk(state, toolkit)
        assert result["stage"] == ModelingStage.MITIGATE.value
        assert len(result["threats"]) == len(threats)

    @pytest.mark.asyncio()
    async def test_recommend_mitigations_node(
        self, toolkit: ThreatModelingToolkit
    ) -> None:
        components = await toolkit.discover_components("web_application")
        threats = await toolkit.analyze_threats(components)
        scored = await toolkit.assess_risk(threats)
        state: dict = {
            "threats": [t.model_dump() for t in scored],
            "reasoning_chain": [],
        }
        result = await recommend_mitigations(state, toolkit)
        assert len(result["mitigations"]) > 0
        assert result["residual_risk"] >= 0.0
        assert result["stage"] == ModelingStage.MITIGATE.value
