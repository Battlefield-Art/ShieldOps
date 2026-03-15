"""Unit tests for ExperimentParameterSearchEngine."""

from __future__ import annotations

import pytest

from shieldops.analytics.experiment_parameter_search_engine import (
    ExperimentParameterSearchEngine,
    ParameterSensitivity,
    SearchPhase,
    SearchStrategy,
)


@pytest.fixture()
def engine() -> ExperimentParameterSearchEngine:
    return ExperimentParameterSearchEngine(max_records=100)


def test_add_record_returns_record(engine: ExperimentParameterSearchEngine) -> None:
    rec = engine.add_record(
        experiment_id="e1",
        parameter_name="lr",
        parameter_value=0.01,
        outcome_score=0.85,
    )
    assert rec.experiment_id == "e1"
    assert rec.parameter_name == "lr"


def test_add_record_count(engine: ExperimentParameterSearchEngine) -> None:
    engine.add_record(experiment_id="e1", parameter_name="lr")
    engine.add_record(experiment_id="e1", parameter_name="bs")
    assert engine.get_stats()["total_records"] == 2


def test_process_found(engine: ExperimentParameterSearchEngine) -> None:
    engine.add_record(experiment_id="e1", parameter_name="lr", outcome_score=0.7)
    rec = engine.add_record(experiment_id="e1", parameter_name="lr", outcome_score=0.9)
    analysis = engine.process(rec.id)
    assert analysis.best_outcome_score == pytest.approx(0.9)  # type: ignore[union-attr]


def test_process_not_found(engine: ExperimentParameterSearchEngine) -> None:
    result = engine.process("no-id")
    assert result["status"] == "not_found"  # type: ignore[index]


def test_generate_report(engine: ExperimentParameterSearchEngine) -> None:
    engine.add_record(
        experiment_id="e1",
        strategy=SearchStrategy.BAYESIAN,
        sensitivity=ParameterSensitivity.HIGH_IMPACT,
        phase=SearchPhase.EXPLORATION,
    )
    report = engine.generate_report()
    assert "bayesian" in report.by_strategy
    assert "high_impact" in report.by_sensitivity


def test_select_next_parameters(engine: ExperimentParameterSearchEngine) -> None:
    engine.add_record(
        experiment_id="e2",
        parameter_name="lr",
        parameter_value=0.01,
        outcome_score=0.8,
    )
    result = engine.select_next_parameters("e2")
    assert result["experiment_id"] == "e2"
    assert len(result["suggestions"]) > 0


def test_select_next_parameters_empty(engine: ExperimentParameterSearchEngine) -> None:
    result = engine.select_next_parameters("nonexistent")
    assert result["next_value"] is None


def test_compute_parameter_sensitivity(engine: ExperimentParameterSearchEngine) -> None:
    for val in [0.001, 0.01, 0.1]:
        engine.add_record(
            experiment_id="e3",
            parameter_name="lr",
            parameter_value=val,
            outcome_score=val * 5,
        )
    result = engine.compute_parameter_sensitivity()
    assert any(r["parameter_name"] == "lr" for r in result)


def test_estimate_remaining_search_value(engine: ExperimentParameterSearchEngine) -> None:
    for s in [0.5, 0.6, 0.7, 0.9]:
        engine.add_record(experiment_id="e4", outcome_score=s)
    result = engine.estimate_remaining_search_value()
    assert any(r["experiment_id"] == "e4" for r in result)


def test_clear_data(engine: ExperimentParameterSearchEngine) -> None:
    engine.add_record(experiment_id="e1")
    engine.clear_data()
    assert engine.get_stats()["total_records"] == 0


def test_ring_buffer_eviction() -> None:
    eng = ExperimentParameterSearchEngine(max_records=3)
    for idx in range(5):
        eng.add_record(experiment_id=f"e{idx}", parameter_name="p")
    assert eng.get_stats()["total_records"] == 3


def test_report_recommendation_negligible(engine: ExperimentParameterSearchEngine) -> None:
    engine.add_record(
        experiment_id="e5",
        sensitivity=ParameterSensitivity.NEGLIGIBLE,
        parameter_name="noise",
    )
    report = engine.generate_report()
    assert any("negligible" in r.lower() for r in report.recommendations)
