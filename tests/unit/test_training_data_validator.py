"""Tests for training_data_validator."""

from __future__ import annotations

from shieldops.agents.training_data_validator.models import (
    DataIssue,
    DataSource,
    TrainingDataValidatorState,
)


class TestEnums:
    def test_dataissue(self) -> None:
        assert DataIssue.LABEL_ERROR == "label_error"
        assert len(DataIssue) >= 3

    def test_datasource(self) -> None:
        assert DataSource.INTERNAL == "internal"
        assert len(DataSource) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = TrainingDataValidatorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = TrainingDataValidatorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
