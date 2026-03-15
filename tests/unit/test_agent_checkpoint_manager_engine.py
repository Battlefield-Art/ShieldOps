"""Unit tests for AgentCheckpointManagerEngine."""

from __future__ import annotations

import pytest

from shieldops.analytics.agent_checkpoint_manager_engine import (
    AgentCheckpointManagerEngine,
    CheckpointQuality,
    CheckpointTrigger,
    RollbackReason,
)


@pytest.fixture()
def engine() -> AgentCheckpointManagerEngine:
    return AgentCheckpointManagerEngine(max_records=100)


def test_add_record_returns_record(engine: AgentCheckpointManagerEngine) -> None:
    rec = engine.add_record(
        agent_id="agent-1",
        checkpoint_id="cp-1",
        metric_score=0.85,
    )
    assert rec.agent_id == "agent-1"
    assert rec.checkpoint_id == "cp-1"


def test_add_record_count(engine: AgentCheckpointManagerEngine) -> None:
    engine.add_record(agent_id="a1", checkpoint_id="cp1")
    engine.add_record(agent_id="a1", checkpoint_id="cp2")
    assert engine.get_stats()["total_records"] == 2


def test_process_found_selects_best(engine: AgentCheckpointManagerEngine) -> None:
    engine.add_record(agent_id="a1", checkpoint_id="cp-low", metric_score=0.5)
    rec = engine.add_record(agent_id="a1", checkpoint_id="cp-high", metric_score=0.9)
    analysis = engine.process(rec.id)
    assert analysis.best_checkpoint_id == "cp-high"  # type: ignore[union-attr]


def test_process_rollback_recommended_for_below_baseline(
    engine: AgentCheckpointManagerEngine,
) -> None:
    rec = engine.add_record(
        agent_id="a2",
        checkpoint_id="cp-bad",
        quality=CheckpointQuality.BELOW_BASELINE,
        metric_score=0.3,
    )
    analysis = engine.process(rec.id)
    assert analysis.rollback_recommended is True  # type: ignore[union-attr]


def test_process_not_found(engine: AgentCheckpointManagerEngine) -> None:
    result = engine.process("bad-id")
    assert result["status"] == "not_found"  # type: ignore[index]


def test_generate_report(engine: AgentCheckpointManagerEngine) -> None:
    engine.add_record(
        agent_id="a1",
        checkpoint_id="cp1",
        trigger=CheckpointTrigger.IMPROVEMENT_FOUND,
        quality=CheckpointQuality.BEST_SO_FAR,
        rollback_reason=RollbackReason.REGRESSION_DETECTED,
        metric_score=0.9,
    )
    report = engine.generate_report()
    assert "improvement_found" in report.by_trigger
    assert "best_so_far" in report.by_quality


def test_evaluate_checkpoint_quality(engine: AgentCheckpointManagerEngine) -> None:
    engine.add_record(
        agent_id="a3", checkpoint_id="cp-a", metric_score=0.7, baseline_score=0.5
    )
    engine.add_record(
        agent_id="a3", checkpoint_id="cp-b", metric_score=0.9, baseline_score=0.5
    )
    result = engine.evaluate_checkpoint_quality("a3")
    assert len(result) == 2
    assert result[0]["metric_score"] >= result[1]["metric_score"]


def test_select_rollback_target(engine: AgentCheckpointManagerEngine) -> None:
    engine.add_record(
        agent_id="a4",
        checkpoint_id="cp-good",
        quality=CheckpointQuality.BEST_SO_FAR,
        metric_score=0.95,
    )
    result = engine.select_rollback_target("a4")
    assert result["rollback_target"] == "cp-good"


def test_select_rollback_target_no_candidates(engine: AgentCheckpointManagerEngine) -> None:
    engine.add_record(
        agent_id="a5",
        checkpoint_id="cp-bad",
        quality=CheckpointQuality.CORRUPTED,
    )
    result = engine.select_rollback_target("a5")
    assert result["rollback_target"] is None


def test_prune_redundant_checkpoints(engine: AgentCheckpointManagerEngine) -> None:
    engine.add_record(agent_id="a6", checkpoint_id="cp-1", metric_score=0.8)
    engine.add_record(agent_id="a6", checkpoint_id="cp-2", metric_score=0.8)
    result = engine.prune_redundant_checkpoints("a6")
    assert result["prune_count"] >= 1


def test_clear_data(engine: AgentCheckpointManagerEngine) -> None:
    engine.add_record(agent_id="a1", checkpoint_id="cp1")
    engine.clear_data()
    assert engine.get_stats()["total_records"] == 0


def test_ring_buffer_eviction() -> None:
    eng = AgentCheckpointManagerEngine(max_records=3)
    for idx in range(5):
        eng.add_record(agent_id="a", checkpoint_id=f"cp-{idx}")
    assert eng.get_stats()["total_records"] == 3
