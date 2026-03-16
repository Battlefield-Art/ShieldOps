"""Tests for the Adaptive Security agent."""

from __future__ import annotations

import pytest

from shieldops.agents.adaptive_security import create_adaptive_security_graph
from shieldops.agents.adaptive_security.models import (
    AdaptationResult,
    AdaptationStage,
    AdaptiveSecurityState,
    BaselineMetrics,
    ReasoningStep,
    ThreatContext,
    ThresholdProposal,
    ThresholdType,
)
from shieldops.agents.adaptive_security.nodes import (
    apply_accepted,
    compute_baseline,
    detect_and_propose,
    evaluate_proposals,
)
from shieldops.agents.adaptive_security.prompts import (
    SYSTEM_APPLY,
    SYSTEM_BASELINE,
    SYSTEM_DETECT_PROPOSE,
    SYSTEM_EVALUATE,
)
from shieldops.agents.adaptive_security.runner import AdaptiveSecurityRunner
from shieldops.agents.adaptive_security.tools import AdaptiveSecurityToolkit

# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------


class TestAdaptiveSecurityModels:
    def test_adaptation_stage_values(self) -> None:
        assert AdaptationStage.BASELINE == "baseline"
        assert AdaptationStage.DETECT_DRIFT == "detect_drift"
        assert AdaptationStage.PROPOSE_ADJUSTMENT == "propose_adjustment"
        assert AdaptationStage.EVALUATE == "evaluate"
        assert AdaptationStage.APPLY == "apply"

    def test_threat_context_values(self) -> None:
        assert ThreatContext.NORMAL == "normal"
        assert ThreatContext.ELEVATED == "elevated"
        assert ThreatContext.ACTIVE_ATTACK == "active_attack"
        assert ThreatContext.POST_INCIDENT == "post_incident"

    def test_threshold_type_values(self) -> None:
        assert ThresholdType.RISK_SCORE == "risk_score"
        assert ThresholdType.ALERT_VOLUME == "alert_volume"
        assert ThresholdType.ANOMALY_SENSITIVITY == "anomaly_sensitivity"
        assert ThresholdType.RESPONSE_URGENCY == "response_urgency"

    def test_baseline_metrics_defaults(self) -> None:
        bm = BaselineMetrics()
        assert bm.entity_type == ""
        assert bm.current_value == 0.0
        assert bm.baseline_value == 0.0
        assert bm.drift_pct == 0.0
        assert bm.window_hours == 24

    def test_threshold_proposal_defaults(self) -> None:
        tp = ThresholdProposal()
        assert tp.threshold_type == ThresholdType.RISK_SCORE
        assert tp.confidence == 0.0
        assert tp.risk == "low"

    def test_adaptation_result_defaults(self) -> None:
        ar = AdaptationResult()
        assert ar.proposal_id == ""
        assert ar.accepted is False
        assert ar.false_positive_delta == 0.0

    def test_reasoning_step_defaults(self) -> None:
        rs = ReasoningStep()
        assert rs.step == ""
        assert rs.confidence == 0.0
        assert rs.metadata == {}

    def test_adaptive_security_state_defaults(self) -> None:
        state = AdaptiveSecurityState()
        assert state.stage == AdaptationStage.BASELINE
        assert state.threat_context == ThreatContext.NORMAL
        assert state.baselines == []
        assert state.proposals == []
        assert state.results == []
        assert state.accepted_count == 0
        assert state.confidence_score == 0.0
        assert state.error == ""


# ---------------------------------------------------------------------------
# Toolkit tests
# ---------------------------------------------------------------------------


class TestAdaptiveSecurityToolkit:
    @pytest.mark.asyncio
    async def test_compute_baselines_mock_host(self) -> None:
        toolkit = AdaptiveSecurityToolkit()
        baselines = await toolkit.compute_baselines(entity_type="host", window_hours=24)
        assert len(baselines) == 4
        assert all(b.entity_type == "host" for b in baselines)
        assert all(isinstance(b.current_value, float) for b in baselines)

    @pytest.mark.asyncio
    async def test_compute_baselines_mock_user(self) -> None:
        toolkit = AdaptiveSecurityToolkit()
        baselines = await toolkit.compute_baselines(entity_type="user")
        assert len(baselines) == 4
        assert all(b.entity_type == "user" for b in baselines)

    @pytest.mark.asyncio
    async def test_compute_baselines_mock_ip(self) -> None:
        toolkit = AdaptiveSecurityToolkit()
        baselines = await toolkit.compute_baselines(entity_type="ip")
        assert len(baselines) == 4

    @pytest.mark.asyncio
    async def test_compute_baselines_unknown_entity_uses_host(self) -> None:
        toolkit = AdaptiveSecurityToolkit()
        baselines = await toolkit.compute_baselines(entity_type="unknown_type")
        assert len(baselines) == 4  # Falls back to host defaults

    @pytest.mark.asyncio
    async def test_detect_drift_no_drifted(self) -> None:
        toolkit = AdaptiveSecurityToolkit()
        baselines = [
            BaselineMetrics(
                entity_type="host",
                metric_name="risk_score",
                current_value=0.35,
                baseline_value=0.35,
                drift_pct=5.0,  # Well below 30% threshold
            )
        ]
        drifted = await toolkit.detect_drift(baselines)
        assert len(drifted) == 0

    @pytest.mark.asyncio
    async def test_detect_drift_with_drifted(self) -> None:
        toolkit = AdaptiveSecurityToolkit()
        baselines = [
            BaselineMetrics(
                entity_type="host",
                metric_name="risk_score",
                current_value=0.60,
                baseline_value=0.35,
                drift_pct=71.4,  # Above 30% threshold
            ),
            BaselineMetrics(
                entity_type="host",
                metric_name="alert_volume",
                current_value=12.5,
                baseline_value=12.0,
                drift_pct=4.2,  # Below threshold
            ),
        ]
        drifted = await toolkit.detect_drift(baselines)
        assert len(drifted) == 1
        assert drifted[0].metric_name == "risk_score"

    @pytest.mark.asyncio
    async def test_propose_threshold_normal_context(self) -> None:
        toolkit = AdaptiveSecurityToolkit()
        metric = BaselineMetrics(
            entity_type="host",
            metric_name="risk_score",
            current_value=0.55,
            baseline_value=0.35,
            drift_pct=57.0,
        )
        proposal = await toolkit.propose_threshold_adjustment(metric, ThreatContext.NORMAL)
        assert proposal.threshold_type == ThresholdType.RISK_SCORE
        assert proposal.proposed_value > 0.0
        assert proposal.confidence > 0.0
        assert proposal.risk in ("low", "medium", "high")

    @pytest.mark.asyncio
    async def test_propose_threshold_active_attack(self) -> None:
        toolkit = AdaptiveSecurityToolkit()
        metric = BaselineMetrics(
            entity_type="host",
            metric_name="risk_score",
            current_value=0.55,
            baseline_value=0.35,
            drift_pct=57.0,
        )
        proposal = await toolkit.propose_threshold_adjustment(metric, ThreatContext.ACTIVE_ATTACK)
        # Active attack uses multiplier 1.0 vs normal 0.5, so more aggressive
        assert proposal.threshold_type == ThresholdType.RISK_SCORE
        assert "active_attack" in proposal.reasoning

    @pytest.mark.asyncio
    async def test_evaluate_proposal_accepted(self) -> None:
        toolkit = AdaptiveSecurityToolkit()
        proposal = ThresholdProposal(
            threshold_type=ThresholdType.RISK_SCORE,
            current_value=0.35,
            proposed_value=0.40,
            reasoning="test",
            confidence=0.8,
            risk="low",
        )
        result = await toolkit.evaluate_proposal(proposal)
        assert result.proposal_id != ""
        assert result.accepted is True  # confidence >= 0.5 and risk != high

    @pytest.mark.asyncio
    async def test_evaluate_proposal_rejected_high_risk(self) -> None:
        toolkit = AdaptiveSecurityToolkit()
        proposal = ThresholdProposal(
            threshold_type=ThresholdType.RISK_SCORE,
            current_value=0.35,
            proposed_value=0.90,
            reasoning="test",
            confidence=0.9,
            risk="high",
        )
        result = await toolkit.evaluate_proposal(proposal)
        assert result.accepted is False

    @pytest.mark.asyncio
    async def test_evaluate_proposal_rejected_low_confidence(self) -> None:
        toolkit = AdaptiveSecurityToolkit()
        proposal = ThresholdProposal(
            threshold_type=ThresholdType.RISK_SCORE,
            current_value=0.35,
            proposed_value=0.40,
            reasoning="test",
            confidence=0.3,
            risk="low",
        )
        result = await toolkit.evaluate_proposal(proposal)
        assert result.accepted is False

    @pytest.mark.asyncio
    async def test_apply_adjustment_mock(self) -> None:
        toolkit = AdaptiveSecurityToolkit()
        proposal = ThresholdProposal(
            threshold_type=ThresholdType.RISK_SCORE,
            current_value=0.35,
            proposed_value=0.40,
        )
        result = await toolkit.apply_adjustment(proposal)
        assert result["applied"] is True
        assert result["threshold_type"] == "risk_score"
        assert result["new_value"] == 0.40
        assert result["mock"] is True


# ---------------------------------------------------------------------------
# Node tests
# ---------------------------------------------------------------------------


class TestAdaptiveSecurityNodes:
    @pytest.mark.asyncio
    async def test_compute_baseline_node(self) -> None:
        toolkit = AdaptiveSecurityToolkit()
        state: dict = {"window_hours": 24, "reasoning_chain": []}
        result = await compute_baseline(state, toolkit)
        assert result["stage"] == "detect_drift"
        assert len(result["baselines"]) == 12  # 4 metrics x 3 entity types
        assert len(result["reasoning_chain"]) == 1

    @pytest.mark.asyncio
    async def test_detect_and_propose_node(self) -> None:
        toolkit = AdaptiveSecurityToolkit()
        # Create baselines with known drift
        baselines = [
            {
                "entity_type": "host",
                "metric_name": "risk_score",
                "current_value": 0.60,
                "baseline_value": 0.35,
                "drift_pct": 71.4,
                "window_hours": 24,
            }
        ]
        state: dict = {
            "baselines": baselines,
            "threat_context": "normal",
            "reasoning_chain": [],
        }
        result = await detect_and_propose(state, toolkit)
        assert result["stage"] == "evaluate"
        assert len(result["proposals"]) == 1

    @pytest.mark.asyncio
    async def test_evaluate_proposals_node(self) -> None:
        toolkit = AdaptiveSecurityToolkit()
        proposals = [
            {
                "threshold_type": "risk_score",
                "current_value": 0.35,
                "proposed_value": 0.40,
                "reasoning": "test",
                "confidence": 0.8,
                "risk": "low",
            }
        ]
        state: dict = {"proposals": proposals, "reasoning_chain": []}
        result = await evaluate_proposals(state, toolkit)
        assert result["stage"] == "apply"
        assert len(result["results"]) == 1
        assert result["accepted_count"] == 1

    @pytest.mark.asyncio
    async def test_apply_accepted_node(self) -> None:
        toolkit = AdaptiveSecurityToolkit()
        proposals = [
            {
                "threshold_type": "risk_score",
                "current_value": 0.35,
                "proposed_value": 0.40,
                "reasoning": "test",
                "confidence": 0.8,
                "risk": "low",
            }
        ]
        results = [
            {
                "proposal_id": "abc123",
                "accepted": True,
                "actual_impact": "reduced FP",
                "false_positive_delta": -0.05,
                "detection_delta": 0.03,
            }
        ]
        state: dict = {
            "proposals": proposals,
            "results": results,
            "reasoning_chain": [],
        }
        result = await apply_accepted(state, toolkit)
        assert result["stage"] == "apply"
        assert "Applied 1 threshold adjustments" in result["reasoning_chain"][-1]


# ---------------------------------------------------------------------------
# Graph and runner tests
# ---------------------------------------------------------------------------


class TestAdaptiveSecurityGraph:
    def test_create_graph(self) -> None:
        graph = create_adaptive_security_graph()
        assert graph is not None

    def test_graph_compiles(self) -> None:
        graph = create_adaptive_security_graph()
        app = graph.compile()
        assert app is not None


class TestAdaptiveSecurityRunner:
    def test_runner_init(self) -> None:
        runner = AdaptiveSecurityRunner()
        assert runner is not None

    @pytest.mark.asyncio
    async def test_runner_run_normal(self) -> None:
        runner = AdaptiveSecurityRunner()
        result = await runner.run(threat_context=ThreatContext.NORMAL, window_hours=12)
        assert "reasoning_chain" in result
        assert len(result.get("reasoning_chain", [])) >= 1

    @pytest.mark.asyncio
    async def test_runner_run_string_context(self) -> None:
        runner = AdaptiveSecurityRunner()
        result = await runner.run(threat_context="elevated", window_hours=24)
        assert "reasoning_chain" in result


# ---------------------------------------------------------------------------
# Prompts tests
# ---------------------------------------------------------------------------


class TestAdaptiveSecurityPrompts:
    def test_prompts_are_strings(self) -> None:
        assert isinstance(SYSTEM_BASELINE, str)
        assert isinstance(SYSTEM_DETECT_PROPOSE, str)
        assert isinstance(SYSTEM_EVALUATE, str)
        assert isinstance(SYSTEM_APPLY, str)

    def test_prompts_are_nonempty(self) -> None:
        assert len(SYSTEM_BASELINE) > 50
        assert len(SYSTEM_DETECT_PROPOSE) > 50
        assert len(SYSTEM_EVALUATE) > 50
        assert len(SYSTEM_APPLY) > 50
