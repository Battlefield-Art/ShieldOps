"""Unit tests for the Security Posture Manager Agent — models, toolkit, nodes, graph."""

from __future__ import annotations

import pytest

from shieldops.agents.security_posture.models import (
    DomainAssessment,
    PostureDomain,
    PostureGap,
    PostureReport,
    PostureStage,
    RiskCategory,
    SecurityPostureState,
)
from shieldops.agents.security_posture.tools import SecurityPostureToolkit

# =====================================================================
# Enum Tests
# =====================================================================


class TestPostureStage:
    """Tests for PostureStage enum."""

    def test_enum_values(self) -> None:
        assert PostureStage.ASSESS == "assess"
        assert PostureStage.SCORE == "score"
        assert PostureStage.PRIORITIZE == "prioritize"
        assert PostureStage.RECOMMEND == "recommend"

    def test_enum_membership(self) -> None:
        assert len(PostureStage) == 4

    def test_string_comparison(self) -> None:
        assert PostureStage("assess") is PostureStage.ASSESS


class TestPostureDomain:
    """Tests for PostureDomain enum."""

    def test_enum_values(self) -> None:
        assert PostureDomain.IDENTITY == "identity"
        assert PostureDomain.NETWORK == "network"
        assert PostureDomain.ENDPOINT == "endpoint"
        assert PostureDomain.CLOUD == "cloud"
        assert PostureDomain.DATA == "data"

    def test_enum_membership(self) -> None:
        assert len(PostureDomain) == 5


class TestRiskCategory:
    """Tests for RiskCategory enum."""

    def test_enum_values(self) -> None:
        assert RiskCategory.CRITICAL == "critical"
        assert RiskCategory.HIGH == "high"
        assert RiskCategory.MEDIUM == "medium"
        assert RiskCategory.LOW == "low"
        assert RiskCategory.INFORMATIONAL == "informational"

    def test_enum_membership(self) -> None:
        assert len(RiskCategory) == 5


# =====================================================================
# Model Tests
# =====================================================================


class TestDomainAssessment:
    """Tests for DomainAssessment model."""

    def test_defaults(self) -> None:
        a = DomainAssessment()
        assert a.domain == PostureDomain.IDENTITY
        assert a.score == 0.0
        assert a.findings == []
        assert a.controls_passing == 0
        assert a.controls_total == 0

    def test_creation_with_fields(self) -> None:
        a = DomainAssessment(
            domain=PostureDomain.CLOUD,
            score=75.5,
            findings=["Finding 1", "Finding 2"],
            controls_passing=20,
            controls_total=30,
        )
        assert a.domain == PostureDomain.CLOUD
        assert a.score == 75.5
        assert len(a.findings) == 2
        assert a.controls_passing == 20

    def test_score_bounds_reject_over_100(self) -> None:
        with pytest.raises(ValueError):
            DomainAssessment(score=101.0)

    def test_score_bounds_reject_negative(self) -> None:
        with pytest.raises(ValueError):
            DomainAssessment(score=-1.0)


class TestPostureGap:
    """Tests for PostureGap model."""

    def test_defaults(self) -> None:
        g = PostureGap()
        assert g.domain == PostureDomain.IDENTITY
        assert g.category == RiskCategory.MEDIUM
        assert g.description == ""
        assert g.remediation == ""
        assert g.effort_hours == 0.0
        assert g.impact_score == 0.0

    def test_creation_with_fields(self) -> None:
        g = PostureGap(
            domain=PostureDomain.NETWORK,
            category=RiskCategory.CRITICAL,
            description="Missing segmentation",
            remediation="Deploy micro-segmentation",
            effort_hours=24.0,
            impact_score=90.0,
        )
        assert g.category == RiskCategory.CRITICAL
        assert g.effort_hours == 24.0

    def test_impact_score_bounds(self) -> None:
        with pytest.raises(ValueError):
            PostureGap(impact_score=101.0)


class TestPostureReport:
    """Tests for PostureReport model."""

    def test_defaults(self) -> None:
        r = PostureReport()
        assert r.overall_score == 0.0
        assert r.domain_scores == {}
        assert r.gaps == []
        assert r.trend == "stable"
        assert r.recommendations == []

    def test_creation_with_fields(self) -> None:
        r = PostureReport(
            overall_score=72.0,
            domain_scores={"identity": 80.0, "network": 64.0},
            trend="improving",
            recommendations=["Fix MFA"],
        )
        assert r.overall_score == 72.0
        assert r.trend == "improving"


class TestSecurityPostureState:
    """Tests for SecurityPostureState model."""

    def test_defaults(self) -> None:
        state = SecurityPostureState()
        assert state.request_id == ""
        assert state.stage == PostureStage.ASSESS
        assert state.assessments == []
        assert state.gaps == []
        assert state.overall_score == 0.0
        assert state.report == {}
        assert state.reasoning_chain == []
        assert state.error == ""

    def test_roundtrip_serialization(self) -> None:
        state = SecurityPostureState(
            request_id="sp-test-1",
            stage=PostureStage.SCORE,
            assessments=[DomainAssessment(domain=PostureDomain.CLOUD, score=65.0)],
        )
        data = state.model_dump()
        restored = SecurityPostureState.model_validate(data)
        assert restored.request_id == "sp-test-1"
        assert len(restored.assessments) == 1


# =====================================================================
# Toolkit Tests
# =====================================================================


class TestAssessDomain:
    """Tests for SecurityPostureToolkit.assess_domain."""

    @pytest.mark.asyncio
    async def test_assess_identity(self) -> None:
        toolkit = SecurityPostureToolkit()
        result = await toolkit.assess_domain(PostureDomain.IDENTITY)
        assert result.domain == PostureDomain.IDENTITY
        assert 0.0 <= result.score <= 100.0
        assert result.controls_total == 25
        assert result.controls_passing <= result.controls_total
        assert len(result.findings) >= 1

    @pytest.mark.asyncio
    async def test_assess_all_domains(self) -> None:
        toolkit = SecurityPostureToolkit()
        for domain in PostureDomain:
            result = await toolkit.assess_domain(domain)
            assert result.domain == domain
            assert result.controls_total > 0

    @pytest.mark.asyncio
    async def test_assess_domain_string_input(self) -> None:
        toolkit = SecurityPostureToolkit()
        result = await toolkit.assess_domain("cloud")
        assert result.domain == PostureDomain.CLOUD
        assert result.controls_total == 35


class TestIdentifyGaps:
    """Tests for SecurityPostureToolkit.identify_gaps."""

    @pytest.mark.asyncio
    async def test_identify_gaps_returns_gaps(self) -> None:
        toolkit = SecurityPostureToolkit()
        assessments = [
            DomainAssessment(
                domain=PostureDomain.CLOUD, score=60.0, controls_passing=21, controls_total=35
            ),
            DomainAssessment(
                domain=PostureDomain.IDENTITY, score=80.0, controls_passing=20, controls_total=25
            ),
        ]
        gaps = await toolkit.identify_gaps(assessments)
        assert len(gaps) > 0
        assert all(isinstance(g, PostureGap) for g in gaps)

    @pytest.mark.asyncio
    async def test_lower_score_produces_more_gaps(self) -> None:
        toolkit = SecurityPostureToolkit()
        low_assessment = [
            DomainAssessment(
                domain=PostureDomain.CLOUD, score=30.0, controls_passing=10, controls_total=35
            )
        ]
        high_assessment = [
            DomainAssessment(
                domain=PostureDomain.CLOUD, score=95.0, controls_passing=33, controls_total=35
            )
        ]
        low_gaps = await toolkit.identify_gaps(low_assessment)
        high_gaps = await toolkit.identify_gaps(high_assessment)
        assert len(low_gaps) >= len(high_gaps)

    @pytest.mark.asyncio
    async def test_empty_assessments(self) -> None:
        toolkit = SecurityPostureToolkit()
        gaps = await toolkit.identify_gaps([])
        assert gaps == []


class TestPrioritizeGaps:
    """Tests for SecurityPostureToolkit.prioritize_gaps."""

    def test_prioritize_by_impact_effort_ratio(self) -> None:
        toolkit = SecurityPostureToolkit()
        gaps = [
            PostureGap(
                domain=PostureDomain.CLOUD,
                category=RiskCategory.MEDIUM,
                description="Low priority",
                effort_hours=20.0,
                impact_score=30.0,
            ),
            PostureGap(
                domain=PostureDomain.IDENTITY,
                category=RiskCategory.CRITICAL,
                description="High priority",
                effort_hours=2.0,
                impact_score=95.0,
            ),
        ]
        result = toolkit.prioritize_gaps(gaps)
        assert result[0].description == "High priority"
        assert result[1].description == "Low priority"

    def test_empty_gaps(self) -> None:
        toolkit = SecurityPostureToolkit()
        assert toolkit.prioritize_gaps([]) == []

    def test_single_gap(self) -> None:
        toolkit = SecurityPostureToolkit()
        gap = PostureGap(description="Only one", impact_score=50.0, effort_hours=5.0)
        result = toolkit.prioritize_gaps([gap])
        assert len(result) == 1


class TestGeneratePostureReport:
    """Tests for SecurityPostureToolkit.generate_posture_report."""

    def test_report_with_assessments_and_gaps(self) -> None:
        toolkit = SecurityPostureToolkit()
        assessments = [
            DomainAssessment(domain=PostureDomain.IDENTITY, score=80.0),
            DomainAssessment(domain=PostureDomain.NETWORK, score=60.0),
        ]
        gaps = [
            PostureGap(
                domain=PostureDomain.NETWORK,
                category=RiskCategory.HIGH,
                description="Missing segmentation",
                impact_score=70.0,
            ),
        ]
        report = toolkit.generate_posture_report(assessments, gaps)
        assert report.overall_score == 70.0
        assert report.domain_scores["identity"] == 80.0
        assert report.domain_scores["network"] == 60.0
        assert len(report.gaps) == 1
        assert len(report.recommendations) >= 1

    def test_report_trend_improving(self) -> None:
        toolkit = SecurityPostureToolkit()
        assessments = [
            DomainAssessment(domain=PostureDomain.IDENTITY, score=90.0),
            DomainAssessment(domain=PostureDomain.CLOUD, score=85.0),
        ]
        report = toolkit.generate_posture_report(assessments, [])
        assert report.trend == "improving"

    def test_report_trend_declining(self) -> None:
        toolkit = SecurityPostureToolkit()
        assessments = [
            DomainAssessment(domain=PostureDomain.IDENTITY, score=40.0),
            DomainAssessment(domain=PostureDomain.CLOUD, score=50.0),
        ]
        report = toolkit.generate_posture_report(assessments, [])
        assert report.trend == "declining"

    def test_report_empty_assessments(self) -> None:
        toolkit = SecurityPostureToolkit()
        report = toolkit.generate_posture_report([], [])
        assert report.overall_score == 0.0
        assert report.domain_scores == {}

    def test_report_critical_gaps_produce_urgent_recommendation(self) -> None:
        toolkit = SecurityPostureToolkit()
        assessments = [DomainAssessment(domain=PostureDomain.CLOUD, score=50.0)]
        gaps = [
            PostureGap(
                domain=PostureDomain.CLOUD,
                category=RiskCategory.CRITICAL,
                description="Public S3 bucket",
                impact_score=95.0,
            ),
        ]
        report = toolkit.generate_posture_report(assessments, gaps)
        urgent = [r for r in report.recommendations if "URGENT" in r]
        assert len(urgent) >= 1


# =====================================================================
# Node Tests (async)
# =====================================================================


class TestAssessDomainsNode:
    """Tests for the assess_domains node function."""

    @pytest.mark.asyncio
    async def test_assess_all_domains(self) -> None:
        from shieldops.agents.security_posture.nodes import assess_domains

        toolkit = SecurityPostureToolkit()
        state: dict = {"request_id": "test-1", "reasoning_chain": []}
        result = await assess_domains(state, toolkit)
        assert len(result["assessments"]) == 5
        assert result["stage"] == PostureStage.SCORE.value
        assert len(result["reasoning_chain"]) == 1


class TestIdentifyGapsNode:
    """Tests for the identify_gaps node function."""

    @pytest.mark.asyncio
    async def test_identify_gaps_from_assessments(self) -> None:
        from shieldops.agents.security_posture.nodes import identify_gaps

        toolkit = SecurityPostureToolkit()
        state: dict = {
            "assessments": [
                DomainAssessment(
                    domain=PostureDomain.CLOUD, score=55.0, controls_passing=19, controls_total=35
                ).model_dump(),
            ],
            "reasoning_chain": [],
        }
        result = await identify_gaps(state, toolkit)
        assert len(result["gaps"]) > 0
        assert result["stage"] == PostureStage.PRIORITIZE.value


class TestPrioritizeRemediationNode:
    """Tests for the prioritize_remediation node function."""

    @pytest.mark.asyncio
    async def test_prioritize_and_score(self) -> None:
        from shieldops.agents.security_posture.nodes import prioritize_remediation

        toolkit = SecurityPostureToolkit()
        state: dict = {
            "assessments": [
                DomainAssessment(domain=PostureDomain.IDENTITY, score=70.0).model_dump(),
            ],
            "gaps": [
                PostureGap(
                    description="Gap A",
                    impact_score=80.0,
                    effort_hours=4.0,
                    category=RiskCategory.HIGH,
                ).model_dump(),
                PostureGap(
                    description="Gap B",
                    impact_score=30.0,
                    effort_hours=20.0,
                    category=RiskCategory.LOW,
                ).model_dump(),
            ],
            "reasoning_chain": [],
        }
        result = await prioritize_remediation(state, toolkit)
        assert result["stage"] == PostureStage.RECOMMEND.value
        assert result["overall_score"] == 70.0
        # Verify prioritization order
        assert result["gaps"][0]["description"] == "Gap A"


# =====================================================================
# Prompt Tests
# =====================================================================


class TestPrompts:
    """Tests for prompt template existence and content."""

    def test_prompts_are_non_empty_strings(self) -> None:
        from shieldops.agents.security_posture.prompts import (
            SYSTEM_ASSESS,
            SYSTEM_IDENTIFY_GAPS,
            SYSTEM_PRIORITIZE,
            SYSTEM_REPORT,
        )

        assert isinstance(SYSTEM_ASSESS, str) and len(SYSTEM_ASSESS) > 50
        assert isinstance(SYSTEM_IDENTIFY_GAPS, str) and len(SYSTEM_IDENTIFY_GAPS) > 50
        assert isinstance(SYSTEM_PRIORITIZE, str) and len(SYSTEM_PRIORITIZE) > 50
        assert isinstance(SYSTEM_REPORT, str) and len(SYSTEM_REPORT) > 50

    def test_assess_prompt_mentions_rba(self) -> None:
        from shieldops.agents.security_posture.prompts import SYSTEM_ASSESS

        assert "RBA" in SYSTEM_ASSESS or "risk" in SYSTEM_ASSESS.lower()

    def test_report_prompt_mentions_trend(self) -> None:
        from shieldops.agents.security_posture.prompts import SYSTEM_REPORT

        assert "trend" in SYSTEM_REPORT.lower()


# =====================================================================
# Graph Structure Tests
# =====================================================================


class TestGraphStructure:
    """Tests for the LangGraph workflow definition."""

    def test_graph_creates_successfully(self) -> None:
        from shieldops.agents.security_posture.graph import (
            create_security_posture_graph,
        )

        graph = create_security_posture_graph()
        assert graph is not None

    def test_graph_compiles(self) -> None:
        from shieldops.agents.security_posture.graph import (
            create_security_posture_graph,
        )

        graph = create_security_posture_graph()
        app = graph.compile()
        assert app is not None
