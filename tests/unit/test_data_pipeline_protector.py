"""Unit tests for data_pipeline_protector agent models."""

from __future__ import annotations

from shieldops.agents.data_pipeline_protector.models import (
    DataPipelineProtectorState,
    DataSourceType,
    DPPStage,
    PipelineRisk,
)


class TestEnums:
    def test_dpp_stage_values(self) -> None:
        assert DPPStage.DISCOVER_PIPELINES == "discover_pipelines"
        assert DPPStage.DETECT_ANOMALIES == "detect_anomalies"
        assert DPPStage.REPORT == "report"

    def test_pipeline_risk(self) -> None:
        assert PipelineRisk.CRITICAL == "critical"
        assert PipelineRisk.LOW == "low"

    def test_data_source_type(self) -> None:
        assert DataSourceType.DATABASE == "database"
        assert DataSourceType.ML_DATASET == "ml_dataset"


class TestState:
    def test_default_state(self) -> None:
        state = DataPipelineProtectorState()
        assert state.request_id == ""
        assert state.stage == DPPStage.DISCOVER_PIPELINES
        assert state.error == ""

    def test_state_with_values(self) -> None:
        state = DataPipelineProtectorState(
            request_id="req-001",
            stage=DPPStage.DETECT_ANOMALIES,
        )
        assert state.stage == DPPStage.DETECT_ANOMALIES
