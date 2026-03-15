"""Unit tests for IterationEfficiencyTrackerEngine."""

from __future__ import annotations

import pytest

from shieldops.analytics.iteration_efficiency_tracker_engine import (
    EfficiencyTrend,
    IterationEfficiencyTrackerEngine,
    IterationType,
    StoppingCriteria,
)


@pytest.fixture()
def engine() -> IterationEfficiencyTrackerEngine:
    return IterationEfficiencyTrackerEngine(max_records=100)


def test_add_record_returns_record(engine: IterationEfficiencyTrackerEngine) -> None:
    rec = engine.add_record(experiment_id="exp-1", iteration_number=1, metric_value=0.7)
    assert rec.experiment_id == "exp-1"
    assert rec.iteration_number == 1


def test_add_record_count(engine: IterationEfficiencyTrackerEngine) -> None:
    engine.add_record(experiment_id="e1", iteration_number=1)
    engine.add_record(experiment_id="e1", iteration_number=2)
    assert engine.get_stats()["total_records"] == 2


def test_process_found(engine: IterationEfficiencyTrackerEngine) -> None:
    engine.add_record(experiment_id="e1", iteration_number=1, metric_value=0.5)
    rec = engine.add_record(experiment_id="e1", iteration_number=2, metric_value=0.6)
    analysis = engine.process(rec.id)
    assert analysis.marginal_improvement == pytest.approx(0.1, abs=0.001)  # type: ignore[union-attr]


def test_process_not_found(engine: IterationEfficiencyTrackerEngine) -> None:
    result = engine.process("missing")
    assert result["status"] == "not_found"  # type: ignore[index]


def test_process_should_stop_negative_trend(engine: IterationEfficiencyTrackerEngine) -> None:
    rec = engine.add_record(
        experiment_id="e2",
        iteration_number=1,
        efficiency_trend=EfficiencyTrend.NEGATIVE,
    )
    analysis = engine.process(rec.id)
    assert analysis.should_stop is True  # type: ignore[union-attr]


def test_generate_report(engine: IterationEfficiencyTrackerEngine) -> None:
    engine.add_record(
        experiment_id="e1",
        iteration_type=IterationType.MINI_BATCH,
        stopping_criteria=StoppingCriteria.CONVERGENCE,
        efficiency_trend=EfficiencyTrend.ACCELERATING,
    )
    report = engine.generate_report()
    assert report.total_records == 1
    assert "mini_batch" in report.by_iteration_type


def test_compute_marginal_improvement(engine: IterationEfficiencyTrackerEngine) -> None:
    for i in range(4):
        engine.add_record(
            experiment_id="e3",
            iteration_number=i,
            metric_value=float(i) * 0.1,
        )
    result = engine.compute_marginal_improvement("e3")
    assert len(result) == 3
    assert all("marginal_improvement" in r for r in result)


def test_detect_diminishing_returns(engine: IterationEfficiencyTrackerEngine) -> None:
    vals = [0.8, 0.6, 0.4, 0.2]
    for i, v in enumerate(vals):
        engine.add_record(experiment_id="e4", iteration_number=i, metric_value=v)
    result = engine.detect_diminishing_returns()
    assert any(r["experiment_id"] == "e4" for r in result)


def test_recommend_early_stopping_negative(engine: IterationEfficiencyTrackerEngine) -> None:
    engine.add_record(
        experiment_id="e5",
        iteration_number=1,
        efficiency_trend=EfficiencyTrend.NEGATIVE,
    )
    result = engine.recommend_early_stopping()
    e5_result = next((r for r in result if r["experiment_id"] == "e5"), None)
    assert e5_result is not None
    assert e5_result["should_stop"] is True


def test_recommend_continue_when_accelerating(engine: IterationEfficiencyTrackerEngine) -> None:
    engine.add_record(
        experiment_id="e6",
        iteration_number=1,
        efficiency_trend=EfficiencyTrend.ACCELERATING,
    )
    result = engine.recommend_early_stopping()
    e6_result = next((r for r in result if r["experiment_id"] == "e6"), None)
    assert e6_result is not None
    assert e6_result["should_stop"] is False


def test_clear_data(engine: IterationEfficiencyTrackerEngine) -> None:
    engine.add_record(experiment_id="e1")
    engine.clear_data()
    assert engine.get_stats()["total_records"] == 0


def test_ring_buffer_eviction() -> None:
    eng = IterationEfficiencyTrackerEngine(max_records=3)
    for idx in range(5):
        eng.add_record(experiment_id=f"e{idx}", iteration_number=idx)
    assert eng.get_stats()["total_records"] == 3
