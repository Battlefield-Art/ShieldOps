"""Unit tests for ImprovementAttributionEngine."""

from __future__ import annotations

import pytest

from shieldops.analytics.improvement_attribution_engine import (
    AttributionConfidence,
    ChangeType,
    ImprovementAttributionEngine,
    ImprovementMagnitude,
)


@pytest.fixture()
def engine() -> ImprovementAttributionEngine:
    return ImprovementAttributionEngine(max_records=100)


def test_add_record_returns_record(engine: ImprovementAttributionEngine) -> None:
    rec = engine.add_record(
        experiment_id="e1",
        change_id="ch-1",
        change_type=ChangeType.PARAMETER_CHANGE,
        improvement_delta=0.05,
    )
    assert rec.experiment_id == "e1"
    assert rec.change_id == "ch-1"


def test_add_record_count(engine: ImprovementAttributionEngine) -> None:
    engine.add_record(experiment_id="e1", change_id="c1")
    engine.add_record(experiment_id="e1", change_id="c2")
    assert engine.get_stats()["total_records"] == 2


def test_process_found(engine: ImprovementAttributionEngine) -> None:
    engine.add_record(
        experiment_id="e1",
        change_type=ChangeType.DATA_CHANGE,
        improvement_delta=0.1,
    )
    rec = engine.add_record(
        experiment_id="e1",
        change_type=ChangeType.PARAMETER_CHANGE,
        improvement_delta=0.2,
    )
    analysis = engine.process(rec.id)
    assert analysis.total_improvement == pytest.approx(0.3, abs=0.001)  # type: ignore[union-attr]


def test_process_primary_driver(engine: ImprovementAttributionEngine) -> None:
    engine.add_record(
        experiment_id="e2",
        change_type=ChangeType.PROMPT_CHANGE,
        improvement_delta=0.5,
    )
    engine.add_record(
        experiment_id="e2",
        change_type=ChangeType.DATA_CHANGE,
        improvement_delta=0.1,
    )
    rec = engine.add_record(
        experiment_id="e2",
        change_type=ChangeType.PROMPT_CHANGE,
        improvement_delta=0.3,
    )
    analysis = engine.process(rec.id)
    assert analysis.primary_driver == "prompt_change"  # type: ignore[union-attr]


def test_process_not_found(engine: ImprovementAttributionEngine) -> None:
    result = engine.process("bad")
    assert result["status"] == "not_found"  # type: ignore[index]


def test_generate_report(engine: ImprovementAttributionEngine) -> None:
    engine.add_record(
        experiment_id="e1",
        change_type=ChangeType.ARCHITECTURE_CHANGE,
        attribution_confidence=AttributionConfidence.CAUSAL,
        magnitude=ImprovementMagnitude.BREAKTHROUGH,
    )
    report = engine.generate_report()
    assert "architecture_change" in report.by_change_type
    assert "causal" in report.by_attribution_confidence


def test_attribute_improvement_to_changes(engine: ImprovementAttributionEngine) -> None:
    engine.add_record(
        experiment_id="e3",
        change_type=ChangeType.PARAMETER_CHANGE,
        improvement_delta=0.1,
        attribution_confidence=AttributionConfidence.CAUSAL,
    )
    engine.add_record(
        experiment_id="e3",
        change_type=ChangeType.DATA_CHANGE,
        improvement_delta=0.05,
        attribution_confidence=AttributionConfidence.CORRELATIONAL,
    )
    result = engine.attribute_improvement_to_changes("e3")
    assert len(result) == 2
    assert result[0]["effective_contribution"] >= result[1]["effective_contribution"]


def test_detect_confounded_experiments(engine: ImprovementAttributionEngine) -> None:
    for _ in range(4):
        engine.add_record(
            experiment_id="e4",
            confounded=True,
            simultaneous_changes=3,
        )
    result = engine.detect_confounded_experiments()
    found = next((r for r in result if r["experiment_id"] == "e4"), None)
    assert found is not None
    assert found["is_problematic"] is True


def test_build_improvement_knowledge_base(engine: ImprovementAttributionEngine) -> None:
    engine.add_record(
        experiment_id="e5",
        change_type=ChangeType.PROMPT_CHANGE,
        improvement_delta=0.1,
        magnitude=ImprovementMagnitude.SIGNIFICANT,
    )
    kb = engine.build_improvement_knowledge_base()
    assert "knowledge_entries" in kb
    assert len(kb["knowledge_entries"]) >= 1


def test_clear_data(engine: ImprovementAttributionEngine) -> None:
    engine.add_record(experiment_id="e1")
    engine.clear_data()
    assert engine.get_stats()["total_records"] == 0


def test_ring_buffer_eviction() -> None:
    eng = ImprovementAttributionEngine(max_records=3)
    for idx in range(5):
        eng.add_record(experiment_id=f"e{idx}")
    assert eng.get_stats()["total_records"] == 3
