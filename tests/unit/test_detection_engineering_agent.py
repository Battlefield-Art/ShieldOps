"""Unit tests for the Detection Engineering Agent — models, toolkit, nodes, graph, and runner."""

from __future__ import annotations

import pytest

from shieldops.agents.detection_engineering.graph import (
    _should_deploy,
    build_graph,
    create_detection_engineering_graph,
)
from shieldops.agents.detection_engineering.models import (
    CoverageGap,
    DetectionEngineeringState,
    DetectionRule,
    DetectionStage,
    RuleStatus,
    RuleType,
    TuningResult,
)
from shieldops.agents.detection_engineering.nodes import (
    assess_coverage,
    backtest_and_tune,
    create_rules,
    deploy_rules,
)
from shieldops.agents.detection_engineering.prompts import (
    SYSTEM_ASSESS_COVERAGE,
    SYSTEM_CREATE_RULES,
    SYSTEM_DEPLOY,
    SYSTEM_TEST_AND_TUNE,
)
from shieldops.agents.detection_engineering.runner import DetectionEngineeringRunner
from shieldops.agents.detection_engineering.tools import DetectionEngineeringToolkit

# =====================================================================
# Enum Tests
# =====================================================================


class TestDetectionStage:
    """Tests for DetectionStage enum."""

    def test_enum_values(self) -> None:
        assert DetectionStage.ASSESS_COVERAGE == "assess_coverage"
        assert DetectionStage.CREATE_RULES == "create_rules"
        assert DetectionStage.TEST_RULES == "test_rules"
        assert DetectionStage.TUNE == "tune"
        assert DetectionStage.DEPLOY == "deploy"

    def test_enum_membership(self) -> None:
        assert len(DetectionStage) == 5

    def test_string_comparison(self) -> None:
        assert DetectionStage("assess_coverage") is DetectionStage.ASSESS_COVERAGE


class TestRuleType:
    """Tests for RuleType enum."""

    def test_enum_values(self) -> None:
        assert RuleType.CORRELATION == "correlation"
        assert RuleType.THRESHOLD == "threshold"
        assert RuleType.ANOMALY == "anomaly"
        assert RuleType.SEQUENCE == "sequence"
        assert RuleType.ML_BASED == "ml_based"

    def test_enum_membership(self) -> None:
        assert len(RuleType) == 5


class TestRuleStatus:
    """Tests for RuleStatus enum."""

    def test_enum_values(self) -> None:
        assert RuleStatus.DRAFT == "draft"
        assert RuleStatus.TESTING == "testing"
        assert RuleStatus.ACTIVE == "active"
        assert RuleStatus.TUNING == "tuning"
        assert RuleStatus.RETIRED == "retired"

    def test_enum_membership(self) -> None:
        assert len(RuleStatus) == 5


# =====================================================================
# Model Tests
# =====================================================================


class TestDetectionRule:
    """Tests for DetectionRule model."""

    def test_defaults(self) -> None:
        rule = DetectionRule()
        assert rule.rule_id == ""
        assert rule.name == ""
        assert rule.rule_type == RuleType.CORRELATION
        assert rule.risk_score == 0
        assert rule.false_positive_rate == 0.0
        assert rule.status == RuleStatus.DRAFT

    def test_creation_with_values(self) -> None:
        rule = DetectionRule(
            rule_id="r001",
            name="Detect Phishing",
            rule_type=RuleType.CORRELATION,
            mitre_tactic="Initial Access",
            mitre_technique="T1566 Phishing",
            query='index=main sourcetype="email:gateway"',
            risk_score=70,
            false_positive_rate=0.03,
            status=RuleStatus.ACTIVE,
        )
        assert rule.rule_id == "r001"
        assert rule.risk_score == 70
        assert rule.status == RuleStatus.ACTIVE

    def test_model_dump(self) -> None:
        rule = DetectionRule(rule_id="r002", name="Test")
        d = rule.model_dump()
        assert d["rule_id"] == "r002"
        assert d["rule_type"] == "correlation"


class TestCoverageGap:
    """Tests for CoverageGap model."""

    def test_defaults(self) -> None:
        gap = CoverageGap()
        assert gap.current_coverage == 0.0
        assert gap.priority == "medium"
        assert gap.suggested_rule_type == RuleType.CORRELATION

    def test_creation_with_values(self) -> None:
        gap = CoverageGap(
            mitre_tactic="Execution",
            mitre_technique="T1059 Command and Scripting Interpreter",
            current_coverage=0.25,
            priority="high",
            suggested_rule_type=RuleType.SEQUENCE,
        )
        assert gap.mitre_tactic == "Execution"
        assert gap.priority == "high"


class TestTuningResult:
    """Tests for TuningResult model."""

    def test_defaults(self) -> None:
        result = TuningResult()
        assert result.rule_id == ""
        assert result.original_fp_rate == 0.0
        assert result.tuned_fp_rate == 0.0

    def test_creation_with_values(self) -> None:
        result = TuningResult(
            rule_id="r001",
            original_fp_rate=0.15,
            tuned_fp_rate=0.03,
            tuning_action="Added allowlist",
            detection_rate_impact=-0.02,
        )
        assert result.tuned_fp_rate < result.original_fp_rate
        assert result.detection_rate_impact < 0


class TestDetectionEngineeringState:
    """Tests for DetectionEngineeringState model."""

    def test_defaults(self) -> None:
        state = DetectionEngineeringState()
        assert state.request_id == ""
        assert state.stage == DetectionStage.ASSESS_COVERAGE
        assert state.coverage_gaps == []
        assert state.rules_created == []
        assert state.rules_deployed == []
        assert state.overall_coverage == 0.0
        assert state.error == ""

    def test_model_dump_roundtrip(self) -> None:
        state = DetectionEngineeringState(request_id="req-1")
        d = state.model_dump()
        restored = DetectionEngineeringState(**d)
        assert restored.request_id == "req-1"


# =====================================================================
# Toolkit Tests
# =====================================================================


class TestDetectionEngineeringToolkit:
    """Tests for DetectionEngineeringToolkit."""

    @pytest.fixture()
    def toolkit(self) -> DetectionEngineeringToolkit:
        return DetectionEngineeringToolkit()

    @pytest.mark.asyncio()
    async def test_assess_mitre_coverage(self, toolkit: DetectionEngineeringToolkit) -> None:
        gaps = await toolkit.assess_mitre_coverage()
        assert isinstance(gaps, list)
        for gap in gaps:
            assert isinstance(gap, CoverageGap)
            assert gap.mitre_tactic != ""
            assert gap.mitre_technique != ""
            assert 0.0 <= gap.current_coverage < 0.6

    @pytest.mark.asyncio()
    async def test_create_detection_rule(self, toolkit: DetectionEngineeringToolkit) -> None:
        gap = CoverageGap(
            mitre_tactic="Initial Access",
            mitre_technique="T1566 Phishing",
            current_coverage=0.1,
            priority="critical",
            suggested_rule_type=RuleType.CORRELATION,
        )
        rule = await toolkit.create_detection_rule(gap)
        assert isinstance(rule, DetectionRule)
        assert rule.rule_id != ""
        assert rule.name != ""
        assert rule.risk_score == 90  # critical priority
        assert rule.status == RuleStatus.DRAFT
        assert "email:gateway" in rule.query

    @pytest.mark.asyncio()
    async def test_test_rule(self, toolkit: DetectionEngineeringToolkit) -> None:
        rule = DetectionRule(rule_id="test-001", name="Test Rule", query="index=main")
        result = await toolkit.test_rule(rule, days=7)
        assert result["rule_id"] == "test-001"
        assert result["days_tested"] == 7
        assert "total_alerts" in result
        assert "false_positive_rate" in result
        assert result["status"] in ("passed", "needs_tuning")

    @pytest.mark.asyncio()
    async def test_tune_rule(self, toolkit: DetectionEngineeringToolkit) -> None:
        rule = DetectionRule(
            rule_id="tune-001",
            name="Noisy Rule",
            false_positive_rate=0.20,
        )
        result = await toolkit.tune_rule(rule, fp_threshold=0.05)
        assert isinstance(result, TuningResult)
        assert result.rule_id == "tune-001"
        assert result.tuned_fp_rate < result.original_fp_rate
        assert result.tuning_action != ""

    @pytest.mark.asyncio()
    async def test_deploy_rule(self, toolkit: DetectionEngineeringToolkit) -> None:
        rule = DetectionRule(rule_id="deploy-001", name="Ready Rule")
        result = await toolkit.deploy_rule(rule)
        assert result["rule_id"] == "deploy-001"
        assert result["deployed"] is True
        assert result["monitoring_enabled"] is True


# =====================================================================
# Node Tests
# =====================================================================


class TestNodes:
    """Tests for node functions."""

    @pytest.fixture()
    def toolkit(self) -> DetectionEngineeringToolkit:
        return DetectionEngineeringToolkit()

    @pytest.mark.asyncio()
    async def test_assess_coverage_node(self, toolkit: DetectionEngineeringToolkit) -> None:
        state: dict = {"request_id": "test", "reasoning_chain": []}
        result = await assess_coverage(state, toolkit)
        assert result["stage"] == DetectionStage.CREATE_RULES.value
        assert isinstance(result["coverage_gaps"], list)
        assert len(result["reasoning_chain"]) > 0

    @pytest.mark.asyncio()
    async def test_create_rules_node(self, toolkit: DetectionEngineeringToolkit) -> None:
        gap = CoverageGap(
            mitre_tactic="Execution",
            mitre_technique="T1059 Command and Scripting Interpreter",
            current_coverage=0.2,
            priority="high",
            suggested_rule_type=RuleType.SEQUENCE,
        )
        state: dict = {
            "coverage_gaps": [gap.model_dump()],
            "reasoning_chain": [],
        }
        result = await create_rules(state, toolkit)
        assert result["stage"] == DetectionStage.TEST_RULES.value
        assert len(result["rules_created"]) == 1
        assert result["rules_created"][0]["mitre_tactic"] == "Execution"

    @pytest.mark.asyncio()
    async def test_backtest_and_tune_node(self, toolkit: DetectionEngineeringToolkit) -> None:
        rule = DetectionRule(
            rule_id="node-test-001",
            name="Test Rule",
            query="index=main",
        )
        state: dict = {
            "rules_created": [rule.model_dump()],
            "reasoning_chain": [],
        }
        result = await backtest_and_tune(state, toolkit)
        assert result["stage"] == DetectionStage.DEPLOY.value
        assert len(result["test_results"]) == 1
        assert len(result["rules_created"]) == 1

    @pytest.mark.asyncio()
    async def test_deploy_rules_node(self, toolkit: DetectionEngineeringToolkit) -> None:
        rule = DetectionRule(
            rule_id="deploy-node-001",
            name="Deploy Ready",
            false_positive_rate=0.02,
        )
        state: dict = {
            "rules_created": [rule.model_dump()],
            "reasoning_chain": [],
        }
        result = await deploy_rules(state, toolkit)
        assert "deploy-node-001" in result["rules_deployed"]

    @pytest.mark.asyncio()
    async def test_deploy_rules_node_skips_high_fp(
        self, toolkit: DetectionEngineeringToolkit
    ) -> None:
        rule = DetectionRule(
            rule_id="high-fp-001",
            name="High FP Rule",
            false_positive_rate=0.15,
        )
        state: dict = {
            "rules_created": [rule.model_dump()],
            "reasoning_chain": [],
        }
        result = await deploy_rules(state, toolkit)
        assert "high-fp-001" not in result["rules_deployed"]


# =====================================================================
# Graph Tests
# =====================================================================


class TestGraph:
    """Tests for graph construction and routing."""

    def test_build_graph(self) -> None:
        toolkit = DetectionEngineeringToolkit()
        graph = build_graph(toolkit)
        assert graph is not None

    def test_create_detection_engineering_graph(self) -> None:
        graph = create_detection_engineering_graph()
        assert graph is not None

    def test_should_deploy_with_low_fp(self) -> None:
        state = {
            "rules_created": [{"false_positive_rate": 0.02}],
            "tuning_results": [],
        }
        assert _should_deploy(state) == "deploy"

    def test_should_deploy_with_high_fp(self) -> None:
        state = {
            "rules_created": [{"false_positive_rate": 0.10}],
            "tuning_results": [],
        }
        assert _should_deploy(state) == "end"

    def test_should_deploy_empty_rules(self) -> None:
        state = {"rules_created": [], "tuning_results": []}
        assert _should_deploy(state) == "end"


# =====================================================================
# Prompt Tests
# =====================================================================


class TestPrompts:
    """Tests for prompt templates."""

    def test_prompts_are_strings(self) -> None:
        assert isinstance(SYSTEM_ASSESS_COVERAGE, str)
        assert isinstance(SYSTEM_CREATE_RULES, str)
        assert isinstance(SYSTEM_TEST_AND_TUNE, str)
        assert isinstance(SYSTEM_DEPLOY, str)

    def test_prompts_are_nonempty(self) -> None:
        assert len(SYSTEM_ASSESS_COVERAGE) > 50
        assert len(SYSTEM_CREATE_RULES) > 50
        assert len(SYSTEM_TEST_AND_TUNE) > 50
        assert len(SYSTEM_DEPLOY) > 50


# =====================================================================
# Runner Tests
# =====================================================================


class TestDetectionEngineeringRunner:
    """Tests for DetectionEngineeringRunner."""

    def test_runner_init(self) -> None:
        runner = DetectionEngineeringRunner()
        assert runner._toolkit is not None
        assert runner._app is not None

    @pytest.mark.asyncio()
    async def test_runner_run(self) -> None:
        runner = DetectionEngineeringRunner()
        result = await runner.run(request_id="test-run-001")
        assert isinstance(result, dict)
        assert "reasoning_chain" in result
