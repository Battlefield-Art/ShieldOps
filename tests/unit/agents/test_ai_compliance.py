"""Tests for shieldops.agents.ai_compliance."""

from __future__ import annotations

import pytest

from shieldops.agents.ai_compliance.models import (
    AIComplianceState,
    AISystemRecord,
    ComplianceRequirement,
    ComplianceStage,
    ControlAssessment,
    ControlStatus,
    EvidencePackage,
    RiskClassification,
)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestEnums:
    def test_compliance_stage_values(self) -> None:
        assert ComplianceStage.COLLECT_INVENTORY == "collect_inventory"
        assert ComplianceStage.CLASSIFY_RISK == "classify_risk"
        assert ComplianceStage.ASSESS_REQUIREMENTS == "assess_requirements"
        assert ComplianceStage.EVALUATE_CONTROLS == "evaluate_controls"
        assert ComplianceStage.GENERATE_EVIDENCE == "generate_evidence"
        assert ComplianceStage.REPORT == "report"
        assert len(ComplianceStage) == 6

    def test_risk_classification_values(self) -> None:
        assert RiskClassification.UNACCEPTABLE == "unacceptable"
        assert RiskClassification.HIGH_RISK == "high_risk"
        assert RiskClassification.LIMITED_RISK == "limited_risk"
        assert RiskClassification.MINIMAL_RISK == "minimal_risk"
        assert len(RiskClassification) == 4

    def test_control_status_values(self) -> None:
        assert ControlStatus.IMPLEMENTED == "implemented"
        assert ControlStatus.PARTIAL == "partial"
        assert ControlStatus.MISSING == "missing"
        assert ControlStatus.NOT_APPLICABLE == "not_applicable"
        assert len(ControlStatus) == 4


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TestModels:
    def test_state_defaults(self) -> None:
        state = AIComplianceState()
        assert state.request_id == ""
        assert state.tenant_id == ""
        assert state.stage == ComplianceStage.COLLECT_INVENTORY
        assert state.frameworks == []
        assert state.systems == []
        assert state.classifications == {}
        assert state.requirements == []
        assert state.assessments == []
        assert state.evidence == []
        assert state.compliance_scores == {}
        assert state.reasoning_chain == []
        assert state.error == ""

    def test_ai_system_record_defaults(self) -> None:
        rec = AISystemRecord()
        assert rec.system_id == ""
        assert rec.risk_classification == RiskClassification.MINIMAL_RISK
        assert rec.data_categories == []
        assert rec.tags == {}

    def test_compliance_requirement_defaults(self) -> None:
        req = ComplianceRequirement()
        assert req.mandatory is True
        assert req.risk_tiers == []
        assert req.evidence_needed == []

    def test_control_assessment_defaults(self) -> None:
        ca = ControlAssessment()
        assert ca.status == ControlStatus.MISSING
        assert ca.score == 0.0

    def test_evidence_package_defaults(self) -> None:
        ep = EvidencePackage()
        assert ep.evidence_id == ""
        assert ep.artifacts == []


# ---------------------------------------------------------------------------
# Toolkit
# ---------------------------------------------------------------------------


class TestToolkit:
    @pytest.fixture()
    def toolkit(self):
        from shieldops.agents.ai_compliance.tools import AIComplianceToolkit

        return AIComplianceToolkit()

    @pytest.mark.asyncio
    async def test_collect_inventory_returns_samples(self, toolkit) -> None:
        systems = await toolkit.collect_inventory("tenant-1")
        assert isinstance(systems, list)
        assert len(systems) >= 1
        assert all(isinstance(s, AISystemRecord) for s in systems)

    def test_classify_risk_employment_is_high(self, toolkit) -> None:
        systems = [
            AISystemRecord(
                system_id="ais-test",
                name="Resume Screener",
                domain="employment",
                model_type="classification",
            )
        ]
        classified = toolkit.classify_risk(systems)
        assert classified[0].risk_classification == RiskClassification.HIGH_RISK

    def test_classify_risk_llm_is_limited(self, toolkit) -> None:
        systems = [
            AISystemRecord(
                system_id="ais-test",
                name="Code Helper",
                domain="internal_tooling",
                model_type="llm",
            )
        ]
        classified = toolkit.classify_risk(systems)
        assert classified[0].risk_classification == RiskClassification.LIMITED_RISK

    def test_classify_risk_unacceptable_pattern(self, toolkit) -> None:
        systems = [
            AISystemRecord(
                system_id="ais-bad",
                name="Social Scorer",
                domain="social_scoring",
                model_type="classification",
            )
        ]
        classified = toolkit.classify_risk(systems)
        assert classified[0].risk_classification == RiskClassification.UNACCEPTABLE

    def test_assess_requirements_eu_ai_act(self, toolkit) -> None:
        systems = [
            AISystemRecord(
                system_id="ais-1",
                risk_classification=RiskClassification.HIGH_RISK,
            )
        ]
        reqs = toolkit.assess_requirements(systems, ["eu_ai_act"])
        assert len(reqs) >= 1
        assert all(isinstance(r, ComplianceRequirement) for r in reqs)
        assert all(r.framework == "eu_ai_act" for r in reqs)

    def test_assess_requirements_nist(self, toolkit) -> None:
        systems = [
            AISystemRecord(
                system_id="ais-1",
                risk_classification=RiskClassification.HIGH_RISK,
            )
        ]
        reqs = toolkit.assess_requirements(systems, ["nist_ai_rmf"])
        assert len(reqs) >= 1

    def test_assess_requirements_unknown_framework(self, toolkit) -> None:
        systems = [
            AISystemRecord(
                system_id="ais-1",
                risk_classification=RiskClassification.HIGH_RISK,
            )
        ]
        reqs = toolkit.assess_requirements(systems, ["unknown_framework"])
        assert reqs == []

    def test_evaluate_controls_production_partial(self, toolkit) -> None:
        systems = [
            AISystemRecord(
                system_id="ais-1",
                risk_classification=RiskClassification.HIGH_RISK,
                deployment_env="production",
            )
        ]
        reqs = [
            ComplianceRequirement(
                requirement_id="REQ-1",
                framework="eu_ai_act",
                title="Test Control",
                risk_tiers=[RiskClassification.HIGH_RISK],
                evidence_needed=["doc_a"],
            )
        ]
        assessments = toolkit.evaluate_controls(systems, reqs)
        assert len(assessments) == 1
        assert assessments[0].status == ControlStatus.PARTIAL
        assert assessments[0].score == 50.0

    def test_evaluate_controls_non_production_missing(self, toolkit) -> None:
        systems = [
            AISystemRecord(
                system_id="ais-1",
                risk_classification=RiskClassification.HIGH_RISK,
                deployment_env="staging",
            )
        ]
        reqs = [
            ComplianceRequirement(
                requirement_id="REQ-1",
                framework="eu_ai_act",
                title="Test Control",
                risk_tiers=[RiskClassification.HIGH_RISK],
                evidence_needed=["doc_a"],
            )
        ]
        assessments = toolkit.evaluate_controls(systems, reqs)
        assert assessments[0].status == ControlStatus.MISSING
        assert assessments[0].score == 0.0

    @pytest.mark.asyncio
    async def test_generate_evidence_creates_packages(self, toolkit) -> None:
        systems = [AISystemRecord(system_id="ais-1", name="Test System")]
        assessments = [
            ControlAssessment(
                assessment_id="CA-1",
                system_id="ais-1",
                framework="eu_ai_act",
                control_name="Test Control",
                status=ControlStatus.PARTIAL,
            )
        ]
        evidence = await toolkit.generate_evidence(systems, assessments)
        assert len(evidence) == 1
        assert isinstance(evidence[0], EvidencePackage)

    def test_calculate_compliance_scores(self, toolkit) -> None:
        assessments = [
            ControlAssessment(framework="eu_ai_act", status=ControlStatus.PARTIAL, score=50.0),
            ControlAssessment(framework="eu_ai_act", status=ControlStatus.IMPLEMENTED, score=100.0),
            ControlAssessment(framework="nist_ai_rmf", status=ControlStatus.MISSING, score=0.0),
        ]
        scores = toolkit.calculate_compliance_scores(assessments)
        assert scores["eu_ai_act"] == 75.0
        assert scores["nist_ai_rmf"] == 0.0


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


class TestGraph:
    def test_graph_compiles(self) -> None:
        from shieldops.agents.ai_compliance.graph import build_graph
        from shieldops.agents.ai_compliance.tools import AIComplianceToolkit

        toolkit = AIComplianceToolkit()
        graph = build_graph(toolkit)
        compiled = graph.compile()
        assert compiled is not None

    def test_create_factory(self) -> None:
        from shieldops.agents.ai_compliance.graph import create_ai_compliance_graph

        graph = create_ai_compliance_graph()
        compiled = graph.compile()
        assert compiled is not None
