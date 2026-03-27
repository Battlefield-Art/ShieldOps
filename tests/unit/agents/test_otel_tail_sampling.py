"""Tests for shieldops.agents.otel_tail_sampling."""

from __future__ import annotations

from shieldops.agents.otel_tail_sampling.models import (
    OTelTailSamplingState,
    PolicyType,
    SamplingDecision,
    SamplingStage,
)


class TestEnums:
    def test_samplingstage_analyze(self):
        assert SamplingStage.ANALYZE == "analyze"

    def test_samplingstage_design_policy(self):
        assert SamplingStage.DESIGN_POLICY == "design_policy"

    def test_samplingstage_simulate(self):
        assert SamplingStage.SIMULATE == "simulate"

    def test_samplingstage_apply(self):
        assert SamplingStage.APPLY == "apply"

    def test_policytype_always_sample(self):
        assert PolicyType.ALWAYS_SAMPLE == "always_sample"

    def test_policytype_latency(self):
        assert PolicyType.LATENCY == "latency"

    def test_policytype_error(self):
        assert PolicyType.ERROR == "error"

    def test_policytype_status_code(self):
        assert PolicyType.STATUS_CODE == "status_code"

    def test_samplingdecision_sample(self):
        assert SamplingDecision.SAMPLE == "sample"

    def test_samplingdecision_drop(self):
        assert SamplingDecision.DROP == "drop"

    def test_samplingdecision_defer(self):
        assert SamplingDecision.DEFER == "defer"


class TestModels:
    def test_state_defaults(self):
        s = OTelTailSamplingState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.otel_tail_sampling.graph import (
            create_otel_tail_sampling_graph,
        )

        sg = create_otel_tail_sampling_graph()
        assert sg.compile() is not None
