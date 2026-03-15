"""Unit tests for ResourceAwareExecutionEngine."""

from __future__ import annotations

import pytest

from shieldops.analytics.resource_aware_execution_engine import (
    ConstraintViolation,
    ExecutionState,
    ResourceAwareExecutionEngine,
    ResourceAwareRecord,
    ResourceConstraint,
)


@pytest.fixture()
def engine() -> ResourceAwareExecutionEngine:
    return ResourceAwareExecutionEngine(max_records=100)


def test_add_record_returns_record(engine: ResourceAwareExecutionEngine) -> None:
    rec = engine.add_record(agent_id="agent-1", limit_value=100.0, current_value=50.0)
    assert isinstance(rec, ResourceAwareRecord)
    assert rec.agent_id == "agent-1"


def test_add_record_count(engine: ResourceAwareExecutionEngine) -> None:
    engine.add_record(agent_id="agent-1")
    engine.add_record(agent_id="agent-2")
    assert engine.get_stats()["total_records"] == 2


def test_process_found_utilization(engine: ResourceAwareExecutionEngine) -> None:
    rec = engine.add_record(agent_id="a1", limit_value=100.0, current_value=80.0)
    analysis = engine.process(rec.id)
    assert analysis.utilization_pct == pytest.approx(80.0)  # type: ignore[union-attr]


def test_process_recommends_throttle(engine: ResourceAwareExecutionEngine) -> None:
    rec = engine.add_record(agent_id="a2", limit_value=100.0, current_value=95.0)
    analysis = engine.process(rec.id)
    assert analysis.recommended_state == ExecutionState.THROTTLED  # type: ignore[union-attr]


def test_process_not_found(engine: ResourceAwareExecutionEngine) -> None:
    result = engine.process("missing")
    assert result["status"] == "not_found"  # type: ignore[index]


def test_generate_report(engine: ResourceAwareExecutionEngine) -> None:
    engine.add_record(
        agent_id="a1",
        constraint=ResourceConstraint.MEMORY_CAP,
        violation=ConstraintViolation.HARD_BREACH,
        limit_value=100.0,
        current_value=120.0,
    )
    report = engine.generate_report()
    assert report.total_records == 1
    assert "memory_cap" in report.by_constraint
    assert any("hard" in r.lower() for r in report.recommendations)


def test_enforce_resource_constraints(engine: ResourceAwareExecutionEngine) -> None:
    engine.add_record(
        agent_id="a3",
        violation=ConstraintViolation.HARD_BREACH,
        limit_value=100.0,
        current_value=110.0,
    )
    result = engine.enforce_resource_constraints()
    assert any(r["agent_id"] == "a3" for r in result)


def test_predict_resource_needs(engine: ResourceAwareExecutionEngine) -> None:
    for i in range(3):
        engine.add_record(
            agent_id="a4",
            limit_value=100.0,
            current_value=float(30 + i * 10),
        )
    predictions = engine.predict_resource_needs()
    assert any(p["agent_id"] == "a4" for p in predictions)


def test_optimize_resource_utilization(engine: ResourceAwareExecutionEngine) -> None:
    for i in range(3):
        engine.add_record(agent_id="a5", limit_value=100.0, current_value=float(10 + i * 5))
    result = engine.optimize_resource_utilization()
    assert any(r["agent_id"] == "a5" for r in result)


def test_clear_data(engine: ResourceAwareExecutionEngine) -> None:
    engine.add_record(agent_id="a1")
    engine.clear_data()
    assert engine.get_stats()["total_records"] == 0


def test_ring_buffer_eviction() -> None:
    eng = ResourceAwareExecutionEngine(max_records=3)
    for idx in range(5):
        eng.add_record(agent_id=f"agent-{idx}", limit_value=100.0, current_value=10.0)
    assert eng.get_stats()["total_records"] == 3


def test_recommend_reduce_allocation(engine: ResourceAwareExecutionEngine) -> None:
    for _ in range(3):
        engine.add_record(agent_id="a6", limit_value=100.0, current_value=5.0)
    result = engine.optimize_resource_utilization()
    agent_result = next((r for r in result if r["agent_id"] == "a6"), None)
    assert agent_result is not None
    assert agent_result["recommendation"] == "reduce_allocation"
