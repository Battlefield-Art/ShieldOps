"""Agent Checkpoint Manager Engine —
evaluate checkpoint quality, select rollback targets,
and prune redundant checkpoints."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CheckpointTrigger(StrEnum):
    IMPROVEMENT_FOUND = "improvement_found"
    PERIODIC = "periodic"
    PHASE_TRANSITION = "phase_transition"
    MANUAL = "manual"


class CheckpointQuality(StrEnum):
    BEST_SO_FAR = "best_so_far"
    ABOVE_BASELINE = "above_baseline"
    BELOW_BASELINE = "below_baseline"
    CORRUPTED = "corrupted"


class RollbackReason(StrEnum):
    REGRESSION_DETECTED = "regression_detected"
    INSTABILITY = "instability"
    RESOURCE_ISSUE = "resource_issue"
    EXPERIMENT_FAILED = "experiment_failed"


# --- Models ---


class AgentCheckpointRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    checkpoint_id: str = ""
    trigger: CheckpointTrigger = CheckpointTrigger.PERIODIC
    quality: CheckpointQuality = CheckpointQuality.ABOVE_BASELINE
    rollback_reason: RollbackReason = RollbackReason.REGRESSION_DETECTED
    metric_score: float = 0.0
    baseline_score: float = 0.0
    size_mb: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AgentCheckpointAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    best_checkpoint_id: str = ""
    quality: CheckpointQuality = CheckpointQuality.ABOVE_BASELINE
    rollback_recommended: bool = False
    redundant_count: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AgentCheckpointReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    by_trigger: dict[str, int] = Field(default_factory=dict)
    by_quality: dict[str, int] = Field(default_factory=dict)
    by_rollback_reason: dict[str, int] = Field(default_factory=dict)
    top_agents: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AgentCheckpointManagerEngine:
    """Evaluate checkpoint quality, select rollback targets,
    and prune redundant checkpoints."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[AgentCheckpointRecord] = []
        self._analyses: dict[str, AgentCheckpointAnalysis] = {}
        logger.info(
            "agent_checkpoint_manager.init",
            max_records=max_records,
        )

    def add_record(
        self,
        agent_id: str = "",
        checkpoint_id: str = "",
        trigger: CheckpointTrigger = CheckpointTrigger.PERIODIC,
        quality: CheckpointQuality = CheckpointQuality.ABOVE_BASELINE,
        rollback_reason: RollbackReason = RollbackReason.REGRESSION_DETECTED,
        metric_score: float = 0.0,
        baseline_score: float = 0.0,
        size_mb: float = 0.0,
        description: str = "",
    ) -> AgentCheckpointRecord:
        record = AgentCheckpointRecord(
            agent_id=agent_id,
            checkpoint_id=checkpoint_id,
            trigger=trigger,
            quality=quality,
            rollback_reason=rollback_reason,
            metric_score=metric_score,
            baseline_score=baseline_score,
            size_mb=size_mb,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "agent_checkpoint.record_added",
            record_id=record.id,
            agent_id=agent_id,
            checkpoint_id=checkpoint_id,
        )
        return record

    def process(self, key: str) -> AgentCheckpointAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        agent_recs = [r for r in self._records if r.agent_id == rec.agent_id]
        best_score = max((r.metric_score for r in agent_recs), default=0.0)
        best_cp = ""
        for r in agent_recs:
            if r.metric_score == best_score:
                best_cp = r.checkpoint_id
                break
        scores = [r.metric_score for r in agent_recs]
        avg_score = sum(scores) / len(scores) if scores else 0.0
        redundant = len([r for r in agent_recs if abs(r.metric_score - avg_score) < 0.001])
        rollback_rec = rec.quality in (
            CheckpointQuality.BELOW_BASELINE,
            CheckpointQuality.CORRUPTED,
        )
        analysis = AgentCheckpointAnalysis(
            agent_id=rec.agent_id,
            best_checkpoint_id=best_cp,
            quality=rec.quality,
            rollback_recommended=rollback_rec,
            redundant_count=max(0, redundant - 1),
            description=f"Agent {rec.agent_id} best_cp={best_cp} rollback={rollback_rec}",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> AgentCheckpointReport:
        by_t: dict[str, int] = {}
        by_q: dict[str, int] = {}
        by_rr: dict[str, int] = {}
        for r in self._records:
            by_t[r.trigger.value] = by_t.get(r.trigger.value, 0) + 1
            by_q[r.quality.value] = by_q.get(r.quality.value, 0) + 1
            by_rr[r.rollback_reason.value] = by_rr.get(r.rollback_reason.value, 0) + 1
        agent_best: dict[str, float] = {}
        for r in self._records:
            if r.agent_id not in agent_best or r.metric_score > agent_best[r.agent_id]:
                agent_best[r.agent_id] = r.metric_score
        top_agents = sorted(agent_best, key=lambda x: agent_best[x], reverse=True)[:10]
        recs_list: list[str] = []
        corrupted = by_q.get("corrupted", 0)
        if corrupted > 0:
            recs_list.append(f"{corrupted} corrupted checkpoints detected — purge immediately")
        below = by_q.get("below_baseline", 0)
        if below > 0:
            recs_list.append(f"{below} below-baseline checkpoints — review agent regressions")
        if not recs_list:
            recs_list.append("Checkpoint health is good")
        return AgentCheckpointReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            by_trigger=by_t,
            by_quality=by_q,
            by_rollback_reason=by_rr,
            top_agents=top_agents,
            recommendations=recs_list,
        )

    def get_stats(self) -> dict[str, Any]:
        q_dist: dict[str, int] = {}
        for r in self._records:
            q_dist[r.quality.value] = q_dist.get(r.quality.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "quality_distribution": q_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("agent_checkpoint_manager.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def evaluate_checkpoint_quality(self, agent_id: str) -> list[dict[str, Any]]:
        """Evaluate the quality of all checkpoints for an agent."""
        agent_recs = sorted(
            [r for r in self._records if r.agent_id == agent_id],
            key=lambda x: x.metric_score,
            reverse=True,
        )
        if not agent_recs:
            return []
        baseline = agent_recs[0].baseline_score if agent_recs else 0.0
        results: list[dict[str, Any]] = []
        for r in agent_recs:
            improvement_pct = 0.0
            if baseline != 0:
                improvement_pct = (r.metric_score - baseline) / abs(baseline) * 100.0
            results.append(
                {
                    "checkpoint_id": r.checkpoint_id,
                    "metric_score": r.metric_score,
                    "quality": r.quality.value,
                    "trigger": r.trigger.value,
                    "improvement_pct": round(improvement_pct, 2),
                    "size_mb": r.size_mb,
                    "age_hours": round((time.time() - r.created_at) / 3600.0, 2),
                }
            )
        return results

    def select_rollback_target(self, agent_id: str) -> dict[str, Any]:
        """Select the best checkpoint to roll back to."""
        candidate_recs = [
            r
            for r in self._records
            if r.agent_id == agent_id
            and r.quality in (CheckpointQuality.BEST_SO_FAR, CheckpointQuality.ABOVE_BASELINE)
        ]
        if not candidate_recs:
            return {"agent_id": agent_id, "rollback_target": None, "reason": "no_candidates"}
        best = max(candidate_recs, key=lambda x: x.metric_score)
        return {
            "agent_id": agent_id,
            "rollback_target": best.checkpoint_id,
            "metric_score": best.metric_score,
            "quality": best.quality.value,
            "age_hours": round((time.time() - best.created_at) / 3600.0, 2),
            "size_mb": best.size_mb,
        }

    def prune_redundant_checkpoints(self, agent_id: str) -> dict[str, Any]:
        """Identify and recommend pruning redundant checkpoints."""
        agent_recs = [r for r in self._records if r.agent_id == agent_id]
        if not agent_recs:
            return {"agent_id": agent_id, "to_prune": [], "kept": []}
        sorted_recs = sorted(agent_recs, key=lambda x: x.metric_score, reverse=True)
        to_keep: list[str] = []
        to_prune: list[str] = []
        seen_scores: list[float] = []
        for r in sorted_recs:
            is_redundant = any(abs(r.metric_score - s) < 0.001 for s in seen_scores)
            if is_redundant or r.quality == CheckpointQuality.CORRUPTED:
                to_prune.append(r.checkpoint_id)
            else:
                to_keep.append(r.checkpoint_id)
                seen_scores.append(r.metric_score)
        return {
            "agent_id": agent_id,
            "to_prune": to_prune,
            "kept": to_keep,
            "prune_count": len(to_prune),
            "keep_count": len(to_keep),
        }
