"""Unit tests for HypothesisExperimentLoopEngine."""

from __future__ import annotations

import pytest

from shieldops.analytics.hypothesis_experiment_loop_engine import (
    ExperimentOutcome,
    HypothesisExperimentLoopEngine,
    HypothesisExperimentRecord,
    HypothesisStatus,
    LoopPhase,
)


@pytest.fixture()
def engine() -> HypothesisExperimentLoopEngine:
    return HypothesisExperimentLoopEngine(max_records=100)


def test_add_record_returns_record(engine: HypothesisExperimentLoopEngine) -> None:
    rec = engine.add_record(hypothesis_id="h1", phase=LoopPhase.HYPOTHESIS)
    assert isinstance(rec, HypothesisExperimentRecord)
    assert rec.hypothesis_id == "h1"


def test_add_record_increments_count(engine: HypothesisExperimentLoopEngine) -> None:
    engine.add_record(hypothesis_id="h1")
    engine.add_record(hypothesis_id="h2")
    assert engine.get_stats()["total_records"] == 2


def test_process_found_advances_phase(engine: HypothesisExperimentLoopEngine) -> None:
    rec = engine.add_record(hypothesis_id="h1", phase=LoopPhase.HYPOTHESIS, confidence=0.8)
    analysis = engine.process(rec.id)
    assert analysis.next_phase == LoopPhase.EXPERIMENT  # type: ignore[union-attr]


def test_process_not_found(engine: HypothesisExperimentLoopEngine) -> None:
    result = engine.process("bad-id")
    assert result["status"] == "not_found"  # type: ignore[index]


def test_generate_report(engine: HypothesisExperimentLoopEngine) -> None:
    engine.add_record(
        hypothesis_id="h1",
        phase=LoopPhase.EVALUATE,
        status=HypothesisStatus.CONFIRMED,
        outcome=ExperimentOutcome.IMPROVEMENT,
    )
    report = engine.generate_report()
    assert report.total_records == 1
    assert "h1" in report.confirmed_hypotheses


def test_advance_loop_phase(engine: HypothesisExperimentLoopEngine) -> None:
    engine.add_record(hypothesis_id="h2", phase=LoopPhase.EXPERIMENT, iterations=3)
    result = engine.advance_loop_phase("h2")
    assert result["current_phase"] == "experiment"
    assert result["next_phase"] == "evaluate"


def test_advance_loop_phase_not_found(engine: HypothesisExperimentLoopEngine) -> None:
    result = engine.advance_loop_phase("missing")
    assert "error" in result


def test_evaluate_hypothesis_evidence_confirmed(engine: HypothesisExperimentLoopEngine) -> None:
    for _ in range(3):
        engine.add_record(
            hypothesis_id="h3",
            outcome=ExperimentOutcome.IMPROVEMENT,
            confidence=0.9,
            improvement_delta=0.1,
        )
    ev = engine.evaluate_hypothesis_evidence("h3")
    assert ev["verdict"] == "confirmed"


def test_evaluate_hypothesis_evidence_rejected(engine: HypothesisExperimentLoopEngine) -> None:
    for _ in range(3):
        engine.add_record(
            hypothesis_id="h4",
            outcome=ExperimentOutcome.REGRESSION,
            confidence=0.2,
            improvement_delta=-0.1,
        )
    ev = engine.evaluate_hypothesis_evidence("h4")
    assert ev["verdict"] in ("rejected", "inconclusive")


def test_select_next_hypothesis_returns_candidate(engine: HypothesisExperimentLoopEngine) -> None:
    engine.add_record(
        hypothesis_id="h5",
        status=HypothesisStatus.PROPOSED,
        confidence=0.7,
        improvement_delta=0.2,
    )
    selection = engine.select_next_hypothesis()
    assert selection["next_hypothesis"] == "h5"


def test_select_next_hypothesis_no_candidates(engine: HypothesisExperimentLoopEngine) -> None:
    engine.add_record(hypothesis_id="h6", status=HypothesisStatus.CONFIRMED)
    selection = engine.select_next_hypothesis()
    assert selection["next_hypothesis"] is None


def test_clear_data(engine: HypothesisExperimentLoopEngine) -> None:
    engine.add_record(hypothesis_id="h1")
    engine.clear_data()
    assert engine.get_stats()["total_records"] == 0
