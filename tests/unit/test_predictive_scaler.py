"""Unit tests for predictive_scaler agent models."""

from __future__ import annotations

from shieldops.agents.predictive_scaler.models import (
    PredictiveScalerState,
    PSStage,
    ResourceType,
    ScalingDirection,
)


class TestEnums:
    def test_ps_stage_values(self) -> None:
        assert PSStage.COLLECT_METRICS == "collect_metrics"
        assert PSStage.PREDICT_DEMAND == "predict_demand"
        assert PSStage.EXECUTE_SCALING == "execute_scaling"
        assert PSStage.REPORT == "report"

    def test_scaling_direction_values(self) -> None:
        assert ScalingDirection.SCALE_UP == "scale_up"
        assert ScalingDirection.SCALE_DOWN == "scale_down"
        assert ScalingDirection.SCALE_OUT == "scale_out"
        assert ScalingDirection.SCALE_IN == "scale_in"
        assert ScalingDirection.NO_CHANGE == "no_change"

    def test_resource_type_values(self) -> None:
        assert ResourceType.COMPUTE == "compute"
        assert ResourceType.MEMORY == "memory"
        assert ResourceType.GPU == "gpu"


class TestState:
    def test_default_state(self) -> None:
        state = PredictiveScalerState()
        assert state.request_id == ""
        assert state.tenant_id == ""
        assert state.stage == PSStage.COLLECT_METRICS
        assert state.error == ""

    def test_state_with_values(self) -> None:
        state = PredictiveScalerState(
            request_id="req-001",
            tenant_id="t-001",
            stage=PSStage.PREDICT_DEMAND,
        )
        assert state.request_id == "req-001"
        assert state.tenant_id == "t-001"
        assert state.stage == PSStage.PREDICT_DEMAND
