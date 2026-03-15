"""Unit tests for LightweightEvalHarnessEngine."""

from __future__ import annotations

import pytest

from shieldops.analytics.lightweight_eval_harness_engine import (
    EvalCost,
    EvalMode,
    EvalReliability,
    LightweightEvalHarnessEngine,
)


@pytest.fixture()
def engine() -> LightweightEvalHarnessEngine:
    return LightweightEvalHarnessEngine(max_records=100)


def test_add_record_returns_record(engine: LightweightEvalHarnessEngine) -> None:
    rec = engine.add_record(experiment_id="e1", eval_score=0.8, proxy_score=0.75)
    assert rec.experiment_id == "e1"
    assert rec.eval_score == 0.8


def test_add_record_count(engine: LightweightEvalHarnessEngine) -> None:
    engine.add_record(experiment_id="e1")
    engine.add_record(experiment_id="e2")
    assert engine.get_stats()["total_records"] == 2


def test_process_found(engine: LightweightEvalHarnessEngine) -> None:
    rec = engine.add_record(
        experiment_id="e1",
        eval_score=0.8,
        proxy_score=0.82,
        eval_cost=EvalCost.CHEAP,
        duration_seconds=5.0,
    )
    analysis = engine.process(rec.id)
    assert analysis.proxy_accuracy_pct > 0  # type: ignore[union-attr]


def test_process_recommends_fast_check_for_expensive(
    engine: LightweightEvalHarnessEngine,
) -> None:
    rec = engine.add_record(
        experiment_id="e2",
        eval_cost=EvalCost.EXPENSIVE,
        eval_score=0.7,
    )
    analysis = engine.process(rec.id)
    assert analysis.recommended_mode == EvalMode.FAST_CHECK  # type: ignore[union-attr]


def test_process_not_found(engine: LightweightEvalHarnessEngine) -> None:
    result = engine.process("bad-id")
    assert result["status"] == "not_found"  # type: ignore[index]


def test_generate_report(engine: LightweightEvalHarnessEngine) -> None:
    engine.add_record(
        experiment_id="e1",
        eval_mode=EvalMode.SAMPLED_SUITE,
        reliability=EvalReliability.HIGH_CONFIDENCE,
        eval_cost=EvalCost.MODERATE,
    )
    report = engine.generate_report()
    assert "sampled_suite" in report.by_eval_mode
    assert "high_confidence" in report.by_reliability


def test_select_eval_mode(engine: LightweightEvalHarnessEngine) -> None:
    engine.add_record(
        experiment_id="e3",
        eval_mode=EvalMode.FAST_CHECK,
        reliability=EvalReliability.HIGH_CONFIDENCE,
        eval_score=0.75,
        duration_seconds=2.0,
    )
    result = engine.select_eval_mode(budget_seconds=10.0, reliability_floor="indicative")
    assert "recommended_mode" in result


def test_select_eval_mode_no_eligible(engine: LightweightEvalHarnessEngine) -> None:
    engine.add_record(
        experiment_id="e4",
        eval_mode=EvalMode.FULL_SUITE,
        reliability=EvalReliability.NOISY,
        eval_score=0.6,
        duration_seconds=100.0,
    )
    result = engine.select_eval_mode(budget_seconds=1.0, reliability_floor="definitive")
    assert result["recommended_mode"] == EvalMode.FAST_CHECK.value


def test_estimate_eval_accuracy(engine: LightweightEvalHarnessEngine) -> None:
    engine.add_record(
        experiment_id="e5",
        eval_mode=EvalMode.FULL_SUITE,
        eval_score=0.9,
    )
    engine.add_record(
        experiment_id="e5",
        eval_mode=EvalMode.FAST_CHECK,
        eval_score=0.85,
    )
    result = engine.estimate_eval_accuracy()
    assert isinstance(result, list)


def test_calibrate_proxy_metrics(engine: LightweightEvalHarnessEngine) -> None:
    for i in range(5):
        engine.add_record(
            experiment_id=f"e{i}",
            eval_mode=EvalMode.PROXY_METRIC,
            proxy_score=0.5 + i * 0.05,
            eval_score=0.55 + i * 0.05,
        )
    result = engine.calibrate_proxy_metrics()
    assert len(result) >= 1
    assert "correlation" in result[0]


def test_clear_data(engine: LightweightEvalHarnessEngine) -> None:
    engine.add_record(experiment_id="e1")
    engine.clear_data()
    assert engine.get_stats()["total_records"] == 0


def test_ring_buffer_eviction() -> None:
    eng = LightweightEvalHarnessEngine(max_records=3)
    for idx in range(5):
        eng.add_record(experiment_id=f"e{idx}")
    assert eng.get_stats()["total_records"] == 3
