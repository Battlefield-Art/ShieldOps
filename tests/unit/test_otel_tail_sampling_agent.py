"""Unit tests for OTel Tail Sampling Agent."""

from __future__ import annotations

import yaml
import pytest

from shieldops.agents.otel_tail_sampling.models import (
    OTelTailSamplingState,
    PolicyType,
    SamplingDecision,
    SamplingPolicy,
    SamplingStage,
    SimulationResult,
    TraceProfile,
)
from shieldops.agents.otel_tail_sampling.tools import OTelTailSamplingToolkit
from shieldops.agents.otel_tail_sampling.nodes import (
    analyze_traces,
    apply_policies,
    design_policies,
    simulate_impact,
)
from shieldops.agents.otel_tail_sampling.graph import (
    build_graph,
    create_otel_tail_sampling_graph,
    _should_apply,
)
from shieldops.agents.otel_tail_sampling.runner import OTelTailSamplingRunner


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------

class TestModels:
    def test_sampling_stage_values(self) -> None:
        assert SamplingStage.ANALYZE == "analyze"
        assert SamplingStage.DESIGN_POLICY == "design_policy"
        assert SamplingStage.SIMULATE == "simulate"
        assert SamplingStage.APPLY == "apply"

    def test_policy_type_values(self) -> None:
        assert PolicyType.ALWAYS_SAMPLE == "always_sample"
        assert PolicyType.LATENCY == "latency"
        assert PolicyType.ERROR == "error"
        assert PolicyType.STATUS_CODE == "status_code"
        assert PolicyType.STRING_ATTRIBUTE == "string_attribute"
        assert PolicyType.RATE_LIMITING == "rate_limiting"
        assert PolicyType.COMPOSITE == "composite"

    def test_sampling_decision_values(self) -> None:
        assert SamplingDecision.SAMPLE == "sample"
        assert SamplingDecision.DROP == "drop"
        assert SamplingDecision.DEFER == "defer"

    def test_sampling_policy_defaults(self) -> None:
        p = SamplingPolicy()
        assert p.name == ""
        assert p.policy_type == PolicyType.ALWAYS_SAMPLE
        assert p.threshold == 0.0
        assert p.attribute_key == ""
        assert p.attribute_values == []
        assert p.sample_rate == 1.0

    def test_trace_profile_defaults(self) -> None:
        tp = TraceProfile()
        assert tp.service == ""
        assert tp.avg_latency_ms == 0.0
        assert tp.error_rate == 0.0
        assert tp.volume_per_min == 0
        assert tp.p99_latency_ms == 0.0

    def test_simulation_result_defaults(self) -> None:
        sr = SimulationResult()
        assert sr.policy_name == ""
        assert sr.traces_sampled == 0
        assert sr.traces_dropped == 0
        assert sr.estimated_cost_reduction == 0.0
        assert sr.coverage_impact == ""

    def test_state_defaults(self) -> None:
        state = OTelTailSamplingState()
        assert state.request_id == ""
        assert state.stage == SamplingStage.ANALYZE
        assert state.trace_profiles == []
        assert state.policies == []
        assert state.simulations == []
        assert state.applied_policies == []
        assert state.cost_savings_pct == 0.0
        assert state.reasoning_chain == []
        assert state.error == ""

    def test_state_roundtrip(self) -> None:
        state = OTelTailSamplingState(
            request_id="test-123",
            stage=SamplingStage.SIMULATE,
            cost_savings_pct=42.5,
        )
        data = state.model_dump()
        restored = OTelTailSamplingState(**data)
        assert restored.request_id == "test-123"
        assert restored.cost_savings_pct == 42.5


# ---------------------------------------------------------------------------
# Toolkit tests
# ---------------------------------------------------------------------------

class TestToolkit:
    def setup_method(self) -> None:
        self.toolkit = OTelTailSamplingToolkit()

    @pytest.mark.asyncio
    async def test_analyze_trace_patterns_returns_profiles(self) -> None:
        profiles = await self.toolkit.analyze_trace_patterns("default")
        assert len(profiles) == 3
        assert all(isinstance(p, TraceProfile) for p in profiles)
        services = {p.service for p in profiles}
        assert "api-gateway" in services
        assert "payment-service" in services
        assert "health-check" in services

    def test_design_policy_error_capture(self) -> None:
        profile = TraceProfile(
            service="payment",
            avg_latency_ms=100.0,
            error_rate=0.05,
            volume_per_min=3000,
            p99_latency_ms=500.0,
        )
        policy = self.toolkit.design_sampling_policy(profile, budget_pct=50.0)
        assert policy.policy_type == PolicyType.ERROR
        assert "payment" in policy.name
        assert policy.sample_rate == 1.0

    def test_design_policy_rate_limiting(self) -> None:
        profile = TraceProfile(
            service="health-check",
            avg_latency_ms=2.0,
            error_rate=0.0,
            volume_per_min=50000,
            p99_latency_ms=5.0,
        )
        policy = self.toolkit.design_sampling_policy(profile, budget_pct=20.0)
        assert policy.policy_type == PolicyType.RATE_LIMITING
        assert "health-check" in policy.name
        assert policy.sample_rate == pytest.approx(0.2)

    def test_design_policy_latency_default(self) -> None:
        profile = TraceProfile(
            service="frontend",
            avg_latency_ms=30.0,
            error_rate=0.005,
            volume_per_min=5000,
            p99_latency_ms=200.0,
        )
        policy = self.toolkit.design_sampling_policy(profile, budget_pct=50.0)
        assert policy.policy_type == PolicyType.LATENCY
        assert policy.threshold == 200.0

    def test_simulate_policy_rate_limiting(self) -> None:
        policy = SamplingPolicy(
            name="test-rate-limit",
            policy_type=PolicyType.RATE_LIMITING,
            threshold=5000.0,
            sample_rate=0.1,
        )
        profile = TraceProfile(service="test", volume_per_min=50000)
        sim = self.toolkit.simulate_policy(policy, profile)
        assert sim.traces_sampled == 5000
        assert sim.traces_dropped == 45000
        assert sim.estimated_cost_reduction == 90.0

    def test_simulate_policy_always_sample(self) -> None:
        policy = SamplingPolicy(
            name="test-always",
            policy_type=PolicyType.ALWAYS_SAMPLE,
        )
        profile = TraceProfile(service="test", volume_per_min=1000)
        sim = self.toolkit.simulate_policy(policy, profile)
        assert sim.traces_sampled == 1000
        assert sim.traces_dropped == 0
        assert sim.estimated_cost_reduction == 0.0

    def test_generate_tail_sampling_yaml_valid(self) -> None:
        policies = [
            SamplingPolicy(
                name="error-policy",
                policy_type=PolicyType.ERROR,
                threshold=0.05,
                sample_rate=1.0,
            ),
            SamplingPolicy(
                name="latency-policy",
                policy_type=PolicyType.LATENCY,
                threshold=500.0,
                sample_rate=0.5,
            ),
            SamplingPolicy(
                name="rate-limit-policy",
                policy_type=PolicyType.RATE_LIMITING,
                threshold=1000.0,
                sample_rate=0.1,
            ),
        ]
        yaml_str = self.toolkit.generate_tail_sampling_yaml(policies)
        parsed = yaml.safe_load(yaml_str)

        # Must have processors.tail_sampling
        assert "processors" in parsed
        assert "tail_sampling" in parsed["processors"]

        ts = parsed["processors"]["tail_sampling"]
        assert ts["decision_wait"] == "10s"
        assert ts["num_traces"] == 100000
        assert "expected_new_traces_per_sec" in ts
        assert "policies" in ts
        assert len(ts["policies"]) == 3

    def test_generate_yaml_latency_policy_structure(self) -> None:
        policies = [
            SamplingPolicy(
                name="svc-latency",
                policy_type=PolicyType.LATENCY,
                threshold=300.0,
            ),
        ]
        yaml_str = self.toolkit.generate_tail_sampling_yaml(policies)
        parsed = yaml.safe_load(yaml_str)
        pol = parsed["processors"]["tail_sampling"]["policies"][0]
        assert pol["name"] == "svc-latency"
        assert pol["type"] == "latency"
        assert pol["latency"]["threshold_ms"] == 300

    def test_generate_yaml_string_attribute_policy(self) -> None:
        policies = [
            SamplingPolicy(
                name="env-filter",
                policy_type=PolicyType.STRING_ATTRIBUTE,
                attribute_key="deployment.environment",
                attribute_values=["production", "staging"],
            ),
        ]
        yaml_str = self.toolkit.generate_tail_sampling_yaml(policies)
        parsed = yaml.safe_load(yaml_str)
        pol = parsed["processors"]["tail_sampling"]["policies"][0]
        assert pol["type"] == "string_attribute"
        assert pol["string_attribute"]["key"] == "deployment.environment"
        assert "production" in pol["string_attribute"]["values"]

    @pytest.mark.asyncio
    async def test_apply_policy_simulated(self) -> None:
        policy = SamplingPolicy(name="test-apply", policy_type=PolicyType.ERROR)
        result = await self.toolkit.apply_policy(policy, "default")
        assert result["status"] == "simulated"
        assert result["policy"] == "test-apply"


# ---------------------------------------------------------------------------
# Node tests
# ---------------------------------------------------------------------------

class TestNodes:
    def setup_method(self) -> None:
        self.toolkit = OTelTailSamplingToolkit()

    @pytest.mark.asyncio
    async def test_analyze_traces_node(self) -> None:
        state: dict = {"target_namespace": "monitoring", "reasoning_chain": []}
        result = await analyze_traces(state, self.toolkit)
        assert result["stage"] == "design_policy"
        assert len(result["trace_profiles"]) == 3
        assert len(result["reasoning_chain"]) > 0

    @pytest.mark.asyncio
    async def test_design_policies_node(self) -> None:
        profiles = [
            TraceProfile(
                service="svc-a", error_rate=0.1, volume_per_min=1000, p99_latency_ms=200.0
            ).model_dump(),
        ]
        state: dict = {
            "trace_profiles": profiles,
            "budget_pct": 50.0,
            "reasoning_chain": [],
        }
        result = await design_policies(state, self.toolkit)
        assert result["stage"] == "simulate"
        assert len(result["policies"]) == 1

    @pytest.mark.asyncio
    async def test_simulate_impact_node(self) -> None:
        profile = TraceProfile(
            service="svc-x", volume_per_min=10000, error_rate=0.01
        ).model_dump()
        policy = SamplingPolicy(
            name="svc-x-latency",
            policy_type=PolicyType.LATENCY,
            threshold=200.0,
            sample_rate=0.5,
        ).model_dump()
        state: dict = {
            "trace_profiles": [profile],
            "policies": [policy],
            "reasoning_chain": [],
        }
        result = await simulate_impact(state, self.toolkit)
        assert result["stage"] == "apply"
        assert len(result["simulations"]) == 1
        assert result["cost_savings_pct"] >= 0

    @pytest.mark.asyncio
    async def test_apply_policies_node(self) -> None:
        policy = SamplingPolicy(
            name="test-pol", policy_type=PolicyType.ERROR
        ).model_dump()
        state: dict = {
            "target_namespace": "default",
            "policies": [policy],
            "reasoning_chain": [],
        }
        result = await apply_policies(state, self.toolkit)
        assert "test-pol" in result["applied_policies"]


# ---------------------------------------------------------------------------
# Graph tests
# ---------------------------------------------------------------------------

class TestGraph:
    def test_should_apply_above_threshold(self) -> None:
        assert _should_apply({"cost_savings_pct": 25.0}) == "apply"

    def test_should_apply_below_threshold(self) -> None:
        assert _should_apply({"cost_savings_pct": 5.0}) == "end"

    def test_should_apply_with_state_object(self) -> None:
        state = OTelTailSamplingState(cost_savings_pct=15.0)
        assert _should_apply(state) == "apply"

    def test_build_graph(self) -> None:
        toolkit = OTelTailSamplingToolkit()
        graph = build_graph(toolkit)
        assert graph is not None

    def test_create_graph_factory(self) -> None:
        graph = create_otel_tail_sampling_graph()
        assert graph is not None


# ---------------------------------------------------------------------------
# Runner tests
# ---------------------------------------------------------------------------

class TestRunner:
    def test_runner_init(self) -> None:
        runner = OTelTailSamplingRunner()
        assert runner._app is not None
