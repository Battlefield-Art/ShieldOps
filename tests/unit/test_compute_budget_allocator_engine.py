"""Unit tests for ComputeBudgetAllocatorEngine."""

from __future__ import annotations

import pytest

from shieldops.analytics.compute_budget_allocator_engine import (
    AllocationStrategy,
    BudgetStatus,
    BudgetUnit,
    ComputeBudgetAllocatorEngine,
    ComputeBudgetAnalysis,
    ComputeBudgetRecord,
    ComputeBudgetReport,
)


@pytest.fixture()
def engine() -> ComputeBudgetAllocatorEngine:
    return ComputeBudgetAllocatorEngine(max_records=100)


def test_add_record_returns_record(engine: ComputeBudgetAllocatorEngine) -> None:
    rec = engine.add_record(experiment_id="exp-1", allocated=100.0, consumed=40.0)
    assert isinstance(rec, ComputeBudgetRecord)
    assert rec.experiment_id == "exp-1"
    assert rec.allocated == 100.0


def test_add_record_persisted(engine: ComputeBudgetAllocatorEngine) -> None:
    engine.add_record(experiment_id="exp-2", allocated=50.0)
    stats = engine.get_stats()
    assert stats["total_records"] == 1


def test_process_found(engine: ComputeBudgetAllocatorEngine) -> None:
    rec = engine.add_record(experiment_id="exp-1", allocated=200.0, consumed=100.0)
    result = engine.process(rec.id)
    assert isinstance(result, ComputeBudgetAnalysis)
    assert result.utilization_pct == pytest.approx(50.0)


def test_process_not_found(engine: ComputeBudgetAllocatorEngine) -> None:
    result = engine.process("nonexistent-id")
    assert isinstance(result, dict)
    assert result["status"] == "not_found"


def test_generate_report_structure(engine: ComputeBudgetAllocatorEngine) -> None:
    engine.add_record(
        experiment_id="exp-1",
        unit=BudgetUnit.GPU_HOURS,
        strategy=AllocationStrategy.PRIORITY_WEIGHTED,
        status=BudgetStatus.NEAR_LIMIT,
        allocated=100.0,
        consumed=80.0,
    )
    report = engine.generate_report()
    assert isinstance(report, ComputeBudgetReport)
    assert report.total_records == 1
    assert "gpu_hours" in report.by_unit
    assert "priority_weighted" in report.by_strategy


def test_allocate_experiment_budget(engine: ComputeBudgetAllocatorEngine) -> None:
    engine.add_record(experiment_id="e1", allocated=100.0, priority=2.0)
    engine.add_record(experiment_id="e2", allocated=100.0, priority=1.0)
    allocations = engine.allocate_experiment_budget(300.0, ["e1", "e2"])
    assert len(allocations) == 2
    totals = sum(a["allocated"] for a in allocations)
    assert totals == pytest.approx(300.0, abs=0.01)


def test_allocate_experiment_budget_empty(engine: ComputeBudgetAllocatorEngine) -> None:
    result = engine.allocate_experiment_budget(100.0, [])
    assert result == []


def test_detect_budget_waste(engine: ComputeBudgetAllocatorEngine) -> None:
    engine.add_record(experiment_id="exp-waste", allocated=1000.0, consumed=10.0)
    waste = engine.detect_budget_waste()
    assert any(w["experiment_id"] == "exp-waste" for w in waste)


def test_detect_budget_waste_no_waste(engine: ComputeBudgetAllocatorEngine) -> None:
    engine.add_record(experiment_id="exp-ok", allocated=100.0, consumed=90.0)
    waste = engine.detect_budget_waste()
    waste_ids = [w["experiment_id"] for w in waste]
    assert "exp-ok" not in waste_ids


def test_forecast_budget_exhaustion(engine: ComputeBudgetAllocatorEngine) -> None:
    engine.add_record(experiment_id="exp-fc", allocated=1000.0, consumed=500.0)
    forecasts = engine.forecast_budget_exhaustion()
    assert isinstance(forecasts, list)


def test_clear_data(engine: ComputeBudgetAllocatorEngine) -> None:
    engine.add_record(experiment_id="exp-1", allocated=100.0)
    result = engine.clear_data()
    assert result["status"] == "cleared"
    assert engine.get_stats()["total_records"] == 0


def test_ring_buffer_eviction() -> None:
    eng = ComputeBudgetAllocatorEngine(max_records=3)
    for idx in range(5):
        eng.add_record(experiment_id=f"exp-{idx}", allocated=10.0)
    assert eng.get_stats()["total_records"] == 3


def test_report_recommendations_exceeded(engine: ComputeBudgetAllocatorEngine) -> None:
    engine.add_record(
        experiment_id="exp-x",
        status=BudgetStatus.EXCEEDED,
        allocated=10.0,
        consumed=15.0,
    )
    report = engine.generate_report()
    assert any("exceeded" in r.lower() for r in report.recommendations)
