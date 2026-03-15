"""Unit tests for SingleMetricFocusEngine."""

from __future__ import annotations

import pytest

from shieldops.analytics.single_metric_focus_engine import (
    DistractionType,
    FocusMetric,
    MetricTrend,
    SingleMetricFocusEngine,
    SingleMetricRecord,
)


@pytest.fixture()
def engine() -> SingleMetricFocusEngine:
    return SingleMetricFocusEngine(max_records=100)


def test_add_record_returns_record(engine: SingleMetricFocusEngine) -> None:
    rec = engine.add_record(experiment_id="e1", metric_value=0.8, baseline_value=0.6)
    assert isinstance(rec, SingleMetricRecord)
    assert rec.experiment_id == "e1"


def test_add_record_count(engine: SingleMetricFocusEngine) -> None:
    engine.add_record(experiment_id="e1")
    engine.add_record(experiment_id="e2")
    assert engine.get_stats()["total_records"] == 2


def test_process_found(engine: SingleMetricFocusEngine) -> None:
    rec = engine.add_record(
        experiment_id="e1",
        metric_value=0.9,
        baseline_value=0.6,
        is_primary=True,
    )
    analysis = engine.process(rec.id)
    assert analysis.improvement_pct == pytest.approx(50.0, abs=0.1)  # type: ignore[union-attr]


def test_process_not_found(engine: SingleMetricFocusEngine) -> None:
    result = engine.process("bad-id")
    assert result["status"] == "not_found"  # type: ignore[index]


def test_process_plateau_detected(engine: SingleMetricFocusEngine) -> None:
    rec = engine.add_record(
        experiment_id="e1",
        trend=MetricTrend.PLATEAU,
        metric_value=0.5,
        is_primary=True,
    )
    analysis = engine.process(rec.id)
    assert analysis.plateau_detected is True  # type: ignore[union-attr]


def test_generate_report_structure(engine: SingleMetricFocusEngine) -> None:
    engine.add_record(
        experiment_id="e1",
        focus_metric=FocusMetric.LATENCY,
        trend=MetricTrend.IMPROVING,
        distraction_type=DistractionType.VANITY_METRIC,
    )
    report = engine.generate_report()
    assert report.total_records == 1
    assert "latency" in report.by_focus_metric


def test_track_metric_trajectory(engine: SingleMetricFocusEngine) -> None:
    for i in range(4):
        engine.add_record(
            experiment_id="e2",
            metric_value=0.5 + i * 0.05,
            is_primary=True,
            trend=MetricTrend.IMPROVING,
        )
    result = engine.track_metric_trajectory("e2")
    assert result["data_points"] == 4
    assert result["overall_trend"] == "improving"


def test_track_metric_trajectory_empty(engine: SingleMetricFocusEngine) -> None:
    result = engine.track_metric_trajectory("nonexistent")
    assert result["trajectory"] == []


def test_detect_metric_distractions(engine: SingleMetricFocusEngine) -> None:
    engine.add_record(experiment_id="e3", is_primary=True)
    engine.add_record(experiment_id="e3", is_primary=False)
    engine.add_record(experiment_id="e3", is_primary=False)
    distractions = engine.detect_metric_distractions()
    assert any(d["experiment_id"] == "e3" for d in distractions)


def test_evaluate_plateau_breakout(engine: SingleMetricFocusEngine) -> None:
    engine.add_record(
        experiment_id="e4",
        trend=MetricTrend.PLATEAU,
        metric_value=1.0,
        is_primary=True,
    )
    engine.add_record(
        experiment_id="e4",
        trend=MetricTrend.PLATEAU,
        metric_value=1.5,
        is_primary=True,
    )
    result = engine.evaluate_plateau_breakout("e4")
    assert result["plateau_detected"] is True


def test_clear_data(engine: SingleMetricFocusEngine) -> None:
    engine.add_record(experiment_id="e1")
    engine.clear_data()
    assert engine.get_stats()["total_records"] == 0


def test_ring_buffer_eviction() -> None:
    eng = SingleMetricFocusEngine(max_records=3)
    for idx in range(5):
        eng.add_record(experiment_id=f"e{idx}")
    assert eng.get_stats()["total_records"] == 3
