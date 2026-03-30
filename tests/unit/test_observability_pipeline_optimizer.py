"""Unit tests for observability_pipeline_optimizer agent models."""

from __future__ import annotations

from shieldops.agents.observability_pipeline_optimizer.models import (
    ObservabilityPipelineOptimizerState,
    OPOStage,
    OptimizationAction,
    PipelineType,
)


class TestEnums:
    def test_opo_stage_values(self) -> None:
        assert OPOStage.AUDIT_PIPELINES == "audit_pipelines"
        assert OPOStage.OPTIMIZE_SAMPLING == "optimize_sampling"
        assert OPOStage.REPORT == "report"

    def test_pipeline_type_values(self) -> None:
        assert PipelineType.TRACES == "traces"
        assert PipelineType.METRICS == "metrics"
        assert PipelineType.LOGS == "logs"

    def test_optimization_action_values(self) -> None:
        assert OptimizationAction.DROP_UNUSED == "drop_unused"
        assert OptimizationAction.TAIL_SAMPLE == "tail_sample"


class TestState:
    def test_default_state(self) -> None:
        state = ObservabilityPipelineOptimizerState()
        assert state.request_id == ""
        assert state.stage == OPOStage.AUDIT_PIPELINES
        assert state.error == ""

    def test_state_with_values(self) -> None:
        state = ObservabilityPipelineOptimizerState(
            request_id="req-001",
            tenant_id="t-001",
            stage=OPOStage.OPTIMIZE_SAMPLING,
        )
        assert state.request_id == "req-001"
        assert state.stage == OPOStage.OPTIMIZE_SAMPLING
