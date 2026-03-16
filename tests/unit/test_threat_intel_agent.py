"""Tests for the Threat Intel Agent LangGraph workflow.

Covers:
- ThreatIntelState model creation, defaults, and field types
- Sub-models: ThreatIndicator, IntelCorrelation, ThreatAssessment, ReasoningStep
- Enums: IntelStage, IntelSource, ThreatConfidence, IndicatorType
- Prompt schemas: CollectionResult, CorrelationResult, AssessmentResult, DistributionResult
- ThreatIntelToolkit initialization, risk scoring, relevance assessment, report generation
- Graph creation (create_threat_intel_graph returns a StateGraph)
- ThreatIntelRunner initialization and list_results
- Node functions (collect_indicators, correlate_observations, assess_threats,
  distribute_intel) with mock state
- Conditional edges (should_distribute)
- Integration: full workflow with simple inputs
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shieldops.agents.threat_intel.graph import (
    create_threat_intel_graph,
    should_distribute,
)
from shieldops.agents.threat_intel.models import (
    IndicatorType,
    IntelCorrelation,
    IntelSource,
    IntelStage,
    ReasoningStep,
    ThreatAssessment,
    ThreatConfidence,
    ThreatIndicator,
    ThreatIntelState,
)
from shieldops.agents.threat_intel.nodes import (
    _get_toolkit,
    assess_threats,
    collect_indicators,
    correlate_observations,
    distribute_intel,
    set_toolkit,
)
from shieldops.agents.threat_intel.prompts import (
    AssessmentResult,
    CollectionResult,
    CorrelationResult,
    DistributionResult,
)
from shieldops.agents.threat_intel.runner import ThreatIntelRunner
from shieldops.agents.threat_intel.tools import ThreatIntelToolkit

# -- Fixtures ----------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_toolkit():
    """Reset the module-level toolkit singleton between tests."""
    import shieldops.agents.threat_intel.nodes as nodes_mod

    original = nodes_mod._toolkit
    nodes_mod._toolkit = None
    yield
    nodes_mod._toolkit = original


@pytest.fixture
def sample_indicator() -> ThreatIndicator:
    return ThreatIndicator(
        value="192.168.1.100",
        indicator_type=IndicatorType.IP,
        source=IntelSource.OSINT,
        confidence=ThreatConfidence.PROBABLE,
        first_seen=datetime(2026, 1, 1, tzinfo=UTC),
        last_seen=datetime(2026, 3, 1, tzinfo=UTC),
        tags=["c2", "botnet"],
        mitre_tactics=["TA0011"],
    )


@pytest.fixture
def base_state() -> ThreatIntelState:
    return ThreatIntelState(
        request_id="ti-test-001",
        sources=[IntelSource.OSINT, IntelSource.INTERNAL],
    )


@pytest.fixture
def assessed_state(sample_indicator: ThreatIndicator) -> ThreatIntelState:
    return ThreatIntelState(
        request_id="ti-test-002",
        sources=[IntelSource.OSINT],
        indicators_collected=[sample_indicator],
        correlations=[
            IntelCorrelation(
                indicator_value="192.168.1.100",
                internal_matches=[{"event": "dns_query"}],
                match_count=1,
                risk_score=6.5,
                entities_affected=["srv-web-01"],
            )
        ],
        assessments=[
            ThreatAssessment(
                indicator_value="192.168.1.100",
                relevance_score=0.85,
                actionable=True,
                recommended_actions=["block_ip", "investigate_matches"],
                ttl_hours=72,
            )
        ],
        high_priority_count=1,
        confidence_score=0.85,
    )


# -- TestEnums ---------------------------------------------------------------


class TestEnums:
    def test_intel_stage_values(self):
        assert IntelStage.COLLECT == "collect"
        assert IntelStage.CORRELATE == "correlate"
        assert IntelStage.ASSESS == "assess"
        assert IntelStage.DISTRIBUTE == "distribute"

    def test_intel_source_values(self):
        assert IntelSource.OSINT == "osint"
        assert IntelSource.COMMERCIAL == "commercial"
        assert IntelSource.ISAC == "isac"
        assert IntelSource.INTERNAL == "internal"
        assert IntelSource.DARK_WEB == "dark_web"

    def test_threat_confidence_values(self):
        assert ThreatConfidence.CONFIRMED == "confirmed"
        assert ThreatConfidence.PROBABLE == "probable"
        assert ThreatConfidence.POSSIBLE == "possible"
        assert ThreatConfidence.UNVERIFIED == "unverified"

    def test_indicator_type_values(self):
        assert IndicatorType.IP == "ip"
        assert IndicatorType.DOMAIN == "domain"
        assert IndicatorType.HASH == "hash"
        assert IndicatorType.URL == "url"
        assert IndicatorType.EMAIL == "email"
        assert IndicatorType.CVE == "cve"


# -- TestState ---------------------------------------------------------------


class TestState:
    def test_default_values(self):
        state = ThreatIntelState()
        assert state.request_id == ""
        assert state.stage == IntelStage.COLLECT
        assert state.sources == []
        assert state.indicators_collected == []
        assert state.correlations == []
        assert state.assessments == []
        assert state.high_priority_count == 0
        assert state.confidence_score == pytest.approx(0.0)
        assert state.distribution_channels == []
        assert state.distribution_results == {}
        assert state.session_start is None
        assert state.session_duration_ms == 0
        assert state.reasoning_chain == []
        assert state.current_step == "init"
        assert state.error is None

    def test_creation_with_custom_values(self, base_state: ThreatIntelState):
        assert base_state.request_id == "ti-test-001"
        assert len(base_state.sources) == 2
        assert IntelSource.OSINT in base_state.sources

    def test_list_fields_are_independent(self):
        s1 = ThreatIntelState()
        s2 = ThreatIntelState()
        s1.sources.append(IntelSource.OSINT)
        assert s2.sources == []

    def test_state_with_error(self):
        state = ThreatIntelState(error="feed timeout", current_step="failed")
        assert state.error == "feed timeout"
        assert state.current_step == "failed"


# -- TestSubModels -----------------------------------------------------------


class TestSubModels:
    def test_threat_indicator_creation(self, sample_indicator: ThreatIndicator):
        assert sample_indicator.value == "192.168.1.100"
        assert sample_indicator.indicator_type == IndicatorType.IP
        assert sample_indicator.source == IntelSource.OSINT
        assert sample_indicator.confidence == ThreatConfidence.PROBABLE
        assert len(sample_indicator.tags) == 2
        assert "TA0011" in sample_indicator.mitre_tactics

    def test_threat_indicator_defaults(self):
        ind = ThreatIndicator(
            value="evil.com",
            indicator_type=IndicatorType.DOMAIN,
            source=IntelSource.OSINT,
        )
        assert ind.confidence == ThreatConfidence.UNVERIFIED
        assert ind.first_seen is None
        assert ind.last_seen is None
        assert ind.tags == []
        assert ind.mitre_tactics == []

    def test_intel_correlation_defaults(self):
        corr = IntelCorrelation(indicator_value="10.0.0.1")
        assert corr.internal_matches == []
        assert corr.match_count == 0
        assert corr.risk_score == pytest.approx(0.0)
        assert corr.entities_affected == []

    def test_intel_correlation_with_matches(self):
        corr = IntelCorrelation(
            indicator_value="bad.com",
            internal_matches=[{"event": "dns_lookup"}],
            match_count=1,
            risk_score=7.5,
            entities_affected=["srv-web-01"],
        )
        assert corr.match_count == 1
        assert corr.risk_score == pytest.approx(7.5)
        assert "srv-web-01" in corr.entities_affected

    def test_threat_assessment_defaults(self):
        assessment = ThreatAssessment(indicator_value="10.0.0.1")
        assert assessment.relevance_score == pytest.approx(0.0)
        assert assessment.actionable is False
        assert assessment.recommended_actions == []
        assert assessment.ttl_hours == 24

    def test_threat_assessment_actionable(self):
        assessment = ThreatAssessment(
            indicator_value="evil.com",
            relevance_score=0.9,
            actionable=True,
            recommended_actions=["block_domain", "update_detection_rules"],
            ttl_hours=168,
        )
        assert assessment.actionable is True
        assert len(assessment.recommended_actions) == 2
        assert assessment.ttl_hours == 168

    def test_reasoning_step_creation(self):
        step = ReasoningStep(
            step_number=1,
            action="collect_indicators",
            input_summary="Query OSINT feeds",
            output_summary="Collected 50 indicators",
        )
        assert step.step_number == 1
        assert step.duration_ms == 0
        assert step.tool_used is None

    def test_reasoning_step_with_tool(self):
        step = ReasoningStep(
            step_number=2,
            action="correlate_observations",
            input_summary="Correlate 50 indicators",
            output_summary="Found 5 matches",
            duration_ms=250,
            tool_used="siem_correlator",
        )
        assert step.tool_used == "siem_correlator"
        assert step.duration_ms == 250


# -- TestPromptSchemas -------------------------------------------------------


class TestPromptSchemas:
    def test_collection_result_fields(self):
        result = CollectionResult(
            summary="Collected 100 indicators",
            indicator_count=100,
            high_confidence_count=15,
            notable_patterns=["C2 infrastructure cluster"],
            recommended_sources=["VirusTotal"],
        )
        assert result.indicator_count == 100
        assert result.high_confidence_count == 15
        assert len(result.notable_patterns) == 1

    def test_correlation_result_fields(self):
        result = CorrelationResult(
            summary="5 indicators matched internally",
            matched_indicators=5,
            critical_matches=["192.168.1.100"],
            affected_entities=["srv-web-01"],
            attack_narrative="C2 beacon to known infrastructure",
        )
        assert result.matched_indicators == 5
        assert len(result.critical_matches) == 1

    def test_assessment_result_fields(self):
        result = AssessmentResult(
            summary="3 actionable threats",
            actionable_count=3,
            top_threats=["Active C2 channel"],
            recommended_actions=["Block IP range"],
            overall_risk="high",
        )
        assert result.actionable_count == 3
        assert result.overall_risk == "high"

    def test_distribution_result_fields(self):
        result = DistributionResult(
            summary="Distributed to 3 channels",
            channels_targeted=["siem", "firewall", "edr"],
            rules_created=5,
            entities_notified=["soc_team"],
        )
        assert result.rules_created == 5
        assert len(result.channels_targeted) == 3


# -- TestToolkit -------------------------------------------------------------


class TestToolkit:
    def test_toolkit_initialization_with_no_deps(self):
        toolkit = ThreatIntelToolkit()
        assert toolkit._feed_clients == {}
        assert toolkit._siem_client is None
        assert toolkit._firewall_client is None
        assert toolkit._edr_client is None
        assert toolkit._notification_client is None

    def test_toolkit_initialization_with_deps(self):
        mock_siem = MagicMock()
        toolkit = ThreatIntelToolkit(siem_client=mock_siem)
        assert toolkit._siem_client is mock_siem

    def test_risk_score_confirmed_with_matches_and_mitre(self):
        score = ThreatIntelToolkit._calculate_risk_score(
            match_count=3, confidence=ThreatConfidence.CONFIRMED, has_mitre=True
        )
        # 7.0 + min(1.5, 2.0) + 1.0 = 9.5
        assert score == pytest.approx(9.5)

    def test_risk_score_unverified_no_matches(self):
        score = ThreatIntelToolkit._calculate_risk_score(
            match_count=0, confidence=ThreatConfidence.UNVERIFIED, has_mitre=False
        )
        assert score == pytest.approx(1.0)

    def test_risk_score_capped_at_10(self):
        score = ThreatIntelToolkit._calculate_risk_score(
            match_count=100, confidence=ThreatConfidence.CONFIRMED, has_mitre=True
        )
        assert score == pytest.approx(10.0)

    def test_risk_score_probable_with_mitre(self):
        score = ThreatIntelToolkit._calculate_risk_score(
            match_count=0, confidence=ThreatConfidence.PROBABLE, has_mitre=True
        )
        # 5.0 + 0 + 1.0 = 6.0
        assert score == pytest.approx(6.0)

    @pytest.mark.asyncio
    async def test_collect_from_feeds_no_clients(self):
        toolkit = ThreatIntelToolkit()
        result = await toolkit.collect_from_feeds([IntelSource.OSINT])
        assert result == []

    @pytest.mark.asyncio
    async def test_collect_from_feeds_with_client(self):
        mock_client = AsyncMock()
        mock_client.fetch_indicators.return_value = [
            {
                "value": "10.0.0.1",
                "type": "ip",
                "confidence": "confirmed",
                "tags": ["c2"],
            }
        ]
        toolkit = ThreatIntelToolkit(feed_clients={"osint": mock_client})
        result = await toolkit.collect_from_feeds([IntelSource.OSINT])
        assert len(result) == 1
        assert result[0].value == "10.0.0.1"
        assert result[0].source == IntelSource.OSINT

    @pytest.mark.asyncio
    async def test_collect_from_feeds_handles_error(self):
        mock_client = AsyncMock()
        mock_client.fetch_indicators.side_effect = RuntimeError("timeout")
        toolkit = ThreatIntelToolkit(feed_clients={"osint": mock_client})
        result = await toolkit.collect_from_feeds([IntelSource.OSINT])
        assert result == []

    @pytest.mark.asyncio
    async def test_correlate_with_internal_no_siem(self):
        toolkit = ThreatIntelToolkit()
        indicator = ThreatIndicator(
            value="evil.com",
            indicator_type=IndicatorType.DOMAIN,
            source=IntelSource.OSINT,
        )
        result = await toolkit.correlate_with_internal([indicator])
        assert len(result) == 1
        assert result[0].match_count == 0

    @pytest.mark.asyncio
    async def test_correlate_with_internal_with_siem(self):
        mock_siem = AsyncMock()
        mock_siem.search.return_value = {
            "matches": [{"event": "dns_query"}],
            "entities": ["srv-web-01"],
        }
        toolkit = ThreatIntelToolkit(siem_client=mock_siem)
        indicator = ThreatIndicator(
            value="evil.com",
            indicator_type=IndicatorType.DOMAIN,
            source=IntelSource.OSINT,
            confidence=ThreatConfidence.CONFIRMED,
        )
        result = await toolkit.correlate_with_internal([indicator])
        assert result[0].match_count == 1
        assert "srv-web-01" in result[0].entities_affected

    @pytest.mark.asyncio
    async def test_assess_relevance_confirmed_with_matches(self, sample_indicator: ThreatIndicator):
        toolkit = ThreatIntelToolkit()
        correlation = IntelCorrelation(
            indicator_value="192.168.1.100",
            match_count=2,
            risk_score=7.0,
        )
        assessment = await toolkit.assess_relevance(sample_indicator, correlation)
        # probable=0.7 + match_boost=0.2 + mitre=0.1 = 1.0
        assert assessment.relevance_score == pytest.approx(1.0)
        assert assessment.actionable is True
        assert "block_ip" in assessment.recommended_actions
        assert assessment.ttl_hours == 72  # probable

    @pytest.mark.asyncio
    async def test_assess_relevance_unverified_no_matches(self):
        toolkit = ThreatIntelToolkit()
        indicator = ThreatIndicator(
            value="1.2.3.4",
            indicator_type=IndicatorType.IP,
            source=IntelSource.OSINT,
            confidence=ThreatConfidence.UNVERIFIED,
        )
        correlation = IntelCorrelation(indicator_value="1.2.3.4")
        assessment = await toolkit.assess_relevance(indicator, correlation)
        assert assessment.relevance_score == pytest.approx(0.1)
        assert assessment.actionable is False
        assert assessment.ttl_hours == 6

    @pytest.mark.asyncio
    async def test_generate_ioc_report(self):
        toolkit = ThreatIntelToolkit()
        assessments = [
            ThreatAssessment(
                indicator_value="evil.com",
                relevance_score=0.9,
                actionable=True,
                recommended_actions=["block_domain"],
                ttl_hours=168,
            ),
            ThreatAssessment(
                indicator_value="benign.com",
                relevance_score=0.1,
                actionable=False,
            ),
        ]
        report = await toolkit.generate_ioc_report(assessments)
        assert report["total_indicators"] == 2
        assert report["actionable_count"] == 1
        assert report["high_priority_count"] == 1
        # Sorted by relevance descending
        assert report["indicators"][0]["value"] == "evil.com"

    @pytest.mark.asyncio
    async def test_distribute_intel_no_clients(self):
        toolkit = ThreatIntelToolkit()
        report = {"indicators": []}
        result = await toolkit.distribute_intel(report, ["siem", "firewall"])
        assert result["siem"]["status"] == "skipped"
        assert result["firewall"]["status"] == "skipped"

    @pytest.mark.asyncio
    async def test_distribute_intel_with_client(self):
        mock_siem = AsyncMock()
        mock_siem.ingest_indicators.return_value = {"ingested": 5}
        toolkit = ThreatIntelToolkit(siem_client=mock_siem)
        report = {"indicators": [{"value": "evil.com"}]}
        result = await toolkit.distribute_intel(report, ["siem"])
        assert result["siem"]["status"] == "success"
        assert result["siem"]["indicators_pushed"] == 1


# -- TestGraph ---------------------------------------------------------------


class TestGraph:
    def test_create_threat_intel_graph_returns_state_graph(self):
        graph = create_threat_intel_graph()
        assert graph is not None
        assert hasattr(graph, "compile")

    def test_graph_has_expected_nodes(self):
        graph = create_threat_intel_graph()
        node_names = set(graph.nodes.keys())
        expected = {
            "collect_indicators",
            "correlate_observations",
            "assess_threats",
            "distribute_intel",
        }
        assert expected.issubset(node_names)

    def test_graph_compiles_without_error(self):
        graph = create_threat_intel_graph()
        app = graph.compile()
        assert app is not None


# -- TestRunner --------------------------------------------------------------


class TestRunner:
    def test_runner_initialization(self):
        with patch(
            "shieldops.agents.threat_intel.runner.create_threat_intel_graph"
        ) as mock_graph_fn:
            mock_graph = MagicMock()
            mock_graph.compile.return_value = MagicMock()
            mock_graph_fn.return_value = mock_graph
            runner = ThreatIntelRunner()
            assert runner._results == {}

    def test_list_results_empty(self):
        with patch(
            "shieldops.agents.threat_intel.runner.create_threat_intel_graph"
        ) as mock_graph_fn:
            mock_graph = MagicMock()
            mock_graph.compile.return_value = MagicMock()
            mock_graph_fn.return_value = mock_graph
            runner = ThreatIntelRunner()
            assert runner.list_results() == []

    def test_list_results_returns_summaries(self):
        with patch(
            "shieldops.agents.threat_intel.runner.create_threat_intel_graph"
        ) as mock_graph_fn:
            mock_graph = MagicMock()
            mock_graph.compile.return_value = MagicMock()
            mock_graph_fn.return_value = mock_graph
            runner = ThreatIntelRunner()
            runner._results["ti-abc"] = ThreatIntelState(
                request_id="ti-abc",
                sources=[IntelSource.OSINT],
                high_priority_count=3,
                confidence_score=0.9,
                current_step="complete",
            )
            summaries = runner.list_results()
            assert len(summaries) == 1
            assert summaries[0]["request_id"] == "ti-abc"
            assert summaries[0]["high_priority"] == 3

    @pytest.mark.asyncio
    async def test_run_success(self):
        mock_app = AsyncMock()
        final_state = ThreatIntelState(
            request_id="ti-run-ok",
            sources=[IntelSource.OSINT],
            high_priority_count=2,
            confidence_score=0.8,
            current_step="complete",
        ).model_dump()
        mock_app.ainvoke.return_value = final_state

        with patch(
            "shieldops.agents.threat_intel.runner.create_threat_intel_graph"
        ) as mock_graph_fn:
            mock_graph = MagicMock()
            mock_graph.compile.return_value = mock_app
            mock_graph_fn.return_value = mock_graph
            runner = ThreatIntelRunner()
            result = await runner.run(sources=[IntelSource.OSINT])

        assert isinstance(result, ThreatIntelState)
        assert result.current_step == "complete"
        assert result.high_priority_count == 2

    @pytest.mark.asyncio
    async def test_run_handles_exception(self):
        mock_app = AsyncMock()
        mock_app.ainvoke.side_effect = RuntimeError("Graph failed")

        with patch(
            "shieldops.agents.threat_intel.runner.create_threat_intel_graph"
        ) as mock_graph_fn:
            mock_graph = MagicMock()
            mock_graph.compile.return_value = mock_app
            mock_graph_fn.return_value = mock_graph
            runner = ThreatIntelRunner()
            result = await runner.run(sources=[IntelSource.OSINT])

        assert result.error == "Graph failed"
        assert result.current_step == "failed"

    def test_get_result_found(self):
        with patch(
            "shieldops.agents.threat_intel.runner.create_threat_intel_graph"
        ) as mock_graph_fn:
            mock_graph = MagicMock()
            mock_graph.compile.return_value = MagicMock()
            mock_graph_fn.return_value = mock_graph
            runner = ThreatIntelRunner()
            state = ThreatIntelState(request_id="ti-lookup")
            runner._results["ti-lookup"] = state
            assert runner.get_result("ti-lookup") is state

    def test_get_result_not_found(self):
        with patch(
            "shieldops.agents.threat_intel.runner.create_threat_intel_graph"
        ) as mock_graph_fn:
            mock_graph = MagicMock()
            mock_graph.compile.return_value = MagicMock()
            mock_graph_fn.return_value = mock_graph
            runner = ThreatIntelRunner()
            assert runner.get_result("nonexistent") is None


# -- TestNodes ---------------------------------------------------------------


class TestNodes:
    @pytest.mark.asyncio
    async def test_collect_indicators_default_sources(self):
        state = ThreatIntelState(request_id="ti-collect-1")
        result = await collect_indicators(state)
        assert result["current_step"] == "collect_indicators"
        assert "session_start" in result
        assert len(result["reasoning_chain"]) == 1
        assert result["stage"] == IntelStage.CORRELATE

    @pytest.mark.asyncio
    async def test_collect_indicators_with_sources(self, base_state: ThreatIntelState):
        result = await collect_indicators(base_state)
        assert result["sources"] == [IntelSource.OSINT, IntelSource.INTERNAL]
        assert isinstance(result["indicators_collected"], list)

    @pytest.mark.asyncio
    async def test_correlate_observations_empty(self):
        state = ThreatIntelState(request_id="ti-corr-empty")
        result = await correlate_observations(state)
        assert result["correlations"] == []
        assert result["current_step"] == "correlate_observations"
        assert result["stage"] == IntelStage.ASSESS

    @pytest.mark.asyncio
    async def test_correlate_observations_with_indicators(self, sample_indicator: ThreatIndicator):
        state = ThreatIntelState(
            request_id="ti-corr-1",
            indicators_collected=[sample_indicator],
        )
        result = await correlate_observations(state)
        assert len(result["correlations"]) == 1
        assert result["correlations"][0].indicator_value == "192.168.1.100"

    @pytest.mark.asyncio
    async def test_assess_threats_empty(self):
        state = ThreatIntelState(request_id="ti-assess-empty")
        result = await assess_threats(state)
        assert result["assessments"] == []
        assert result["high_priority_count"] == 0
        assert result["confidence_score"] == pytest.approx(0.0)
        assert result["stage"] == IntelStage.DISTRIBUTE

    @pytest.mark.asyncio
    async def test_assess_threats_with_data(self, sample_indicator: ThreatIndicator):
        correlation = IntelCorrelation(
            indicator_value="192.168.1.100",
            match_count=1,
            risk_score=6.0,
        )
        state = ThreatIntelState(
            request_id="ti-assess-1",
            indicators_collected=[sample_indicator],
            correlations=[correlation],
        )
        result = await assess_threats(state)
        assert len(result["assessments"]) == 1
        assert result["assessments"][0].actionable is True
        assert result["confidence_score"] > 0.0

    @pytest.mark.asyncio
    async def test_distribute_intel_default_channels(self):
        state = ThreatIntelState(
            request_id="ti-dist-1",
            assessments=[
                ThreatAssessment(
                    indicator_value="evil.com",
                    relevance_score=0.9,
                    actionable=True,
                )
            ],
        )
        result = await distribute_intel(state)
        assert result["current_step"] == "complete"
        assert "siem" in result["distribution_channels"]
        assert isinstance(result["distribution_results"], dict)

    @pytest.mark.asyncio
    async def test_distribute_intel_custom_channels(self):
        state = ThreatIntelState(
            request_id="ti-dist-2",
            assessments=[],
            distribution_channels=["siem", "edr"],
        )
        result = await distribute_intel(state)
        assert result["distribution_channels"] == ["siem", "edr"]


# -- TestConditionalEdges ----------------------------------------------------


class TestConditionalEdges:
    def test_should_distribute_high_priority(self, assessed_state: ThreatIntelState):
        assert should_distribute(assessed_state) == "distribute_intel"

    def test_should_distribute_actionable_no_high_priority(self):
        state = ThreatIntelState(
            high_priority_count=0,
            assessments=[
                ThreatAssessment(
                    indicator_value="x",
                    relevance_score=0.6,
                    actionable=True,
                )
            ],
        )
        assert should_distribute(state) == "distribute_intel"

    def test_should_distribute_no_actionable(self):
        from langgraph.graph import END

        state = ThreatIntelState(
            high_priority_count=0,
            assessments=[
                ThreatAssessment(
                    indicator_value="x",
                    relevance_score=0.1,
                    actionable=False,
                )
            ],
        )
        assert should_distribute(state) == END

    def test_should_distribute_with_error(self):
        from langgraph.graph import END

        state = ThreatIntelState(error="something broke")
        assert should_distribute(state) == END

    def test_should_distribute_empty_assessments(self):
        from langgraph.graph import END

        state = ThreatIntelState(assessments=[])
        assert should_distribute(state) == END


# -- TestToolkitManagement ---------------------------------------------------


class TestToolkitManagement:
    def test_get_toolkit_returns_default_when_none_set(self):
        toolkit = _get_toolkit()
        assert isinstance(toolkit, ThreatIntelToolkit)

    def test_set_toolkit_is_used_by_get_toolkit(self):
        custom = ThreatIntelToolkit(siem_client=MagicMock())
        set_toolkit(custom)
        assert _get_toolkit() is custom


# -- TestIntegration ---------------------------------------------------------


class TestIntegration:
    @pytest.mark.asyncio
    async def test_full_workflow_no_indicators(self):
        """A clean run with no feeds configured: collect -> correlate -> assess -> end."""
        state = ThreatIntelState(
            request_id="ti-int-clean",
            sources=[IntelSource.OSINT],
        )

        r1 = await collect_indicators(state)
        state = ThreatIntelState(**{**state.model_dump(), **r1})
        assert state.current_step == "collect_indicators"
        assert state.indicators_collected == []

        r2 = await correlate_observations(state)
        state = ThreatIntelState(**{**state.model_dump(), **r2})
        assert state.current_step == "correlate_observations"

        r3 = await assess_threats(state)
        state = ThreatIntelState(**{**state.model_dump(), **r3})
        assert state.current_step == "assess_threats"
        assert state.high_priority_count == 0

        # Should skip distribution
        assert should_distribute(state) == "__end__"

    @pytest.mark.asyncio
    async def test_full_workflow_with_indicators(self, sample_indicator: ThreatIndicator):
        """When indicators are present, full pipeline runs through distribute."""
        state = ThreatIntelState(
            request_id="ti-int-full",
            sources=[IntelSource.OSINT],
            indicators_collected=[sample_indicator],
        )

        r2 = await correlate_observations(state)
        state = ThreatIntelState(**{**state.model_dump(), **r2})
        assert len(state.correlations) == 1

        r3 = await assess_threats(state)
        state = ThreatIntelState(**{**state.model_dump(), **r3})
        assert len(state.assessments) == 1
        assert state.assessments[0].actionable is True

        # Should distribute since actionable
        assert should_distribute(state) == "distribute_intel"

        r4 = await distribute_intel(state)
        assert r4["current_step"] == "complete"
        assert len(r4["reasoning_chain"]) > len(state.reasoning_chain)
