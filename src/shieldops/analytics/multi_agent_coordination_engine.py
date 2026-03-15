"""Multi-Agent Coordination Engine — routing, load balancing, conflict resolution."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CoordinationMode(StrEnum):
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    PIPELINE = "pipeline"
    HIERARCHICAL = "hierarchical"


class ConflictType(StrEnum):
    RESOURCE_CONTENTION = "resource_contention"
    ACTION_CONFLICT = "action_conflict"
    STATE_INCONSISTENCY = "state_inconsistency"
    PRIORITY_CLASH = "priority_clash"


class ResolutionStrategy(StrEnum):
    PRIORITY_BASED = "priority_based"
    CONSENSUS = "consensus"
    TIMEOUT = "timeout"
    ESCALATION = "escalation"


# --- Models ---


class CoordinationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    task_id: str = ""
    coordination_mode: CoordinationMode = CoordinationMode.SEQUENTIAL
    conflict_type: ConflictType = ConflictType.RESOURCE_CONTENTION
    resolution_strategy: ResolutionStrategy = ResolutionStrategy.PRIORITY_BASED
    overhead_ms: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CoordinationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    task_id: str = ""
    coordination_mode: CoordinationMode = CoordinationMode.SEQUENTIAL
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CoordinationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    high_overhead_count: int = 0
    avg_overhead_ms: float = 0.0
    by_mode: dict[str, int] = Field(default_factory=dict)
    by_conflict: dict[str, int] = Field(default_factory=dict)
    by_resolution: dict[str, int] = Field(default_factory=dict)
    top_high_overhead: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class MultiAgentCoordinationEngine:
    """Optimize coordination between multiple agents — routing, conflicts."""

    def __init__(
        self,
        max_records: int = 200000,
        overhead_threshold: float = 500.0,
    ) -> None:
        self._max_records = max_records
        self._overhead_threshold = overhead_threshold
        self._records: list[CoordinationRecord] = []
        self._analyses: list[CoordinationAnalysis] = []
        logger.info(
            "multi_agent_coordination_engine.initialized",
            max_records=max_records,
            overhead_threshold=overhead_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        task_id: str,
        coordination_mode: CoordinationMode = CoordinationMode.SEQUENTIAL,
        conflict_type: ConflictType = ConflictType.RESOURCE_CONTENTION,
        resolution_strategy: ResolutionStrategy = ResolutionStrategy.PRIORITY_BASED,
        overhead_ms: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> CoordinationRecord:
        record = CoordinationRecord(
            task_id=task_id,
            coordination_mode=coordination_mode,
            conflict_type=conflict_type,
            resolution_strategy=resolution_strategy,
            overhead_ms=overhead_ms,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "multi_agent_coordination_engine.record_added",
            record_id=record.id,
            task_id=task_id,
            coordination_mode=coordination_mode.value,
            overhead_ms=overhead_ms,
        )
        return record

    def get_record(self, record_id: str) -> CoordinationRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        coordination_mode: CoordinationMode | None = None,
        conflict_type: ConflictType | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[CoordinationRecord]:
        results = list(self._records)
        if coordination_mode is not None:
            results = [r for r in results if r.coordination_mode == coordination_mode]
        if conflict_type is not None:
            results = [r for r in results if r.conflict_type == conflict_type]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        task_id: str,
        coordination_mode: CoordinationMode = CoordinationMode.SEQUENTIAL,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> CoordinationAnalysis:
        analysis = CoordinationAnalysis(
            task_id=task_id,
            coordination_mode=coordination_mode,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "multi_agent_coordination_engine.analysis_added",
            task_id=task_id,
            coordination_mode=coordination_mode.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def detect_coordination_conflicts(self) -> list[dict[str, Any]]:
        """Find active agent conflicts sorted by overhead descending."""
        conflicts: list[dict[str, Any]] = []
        for r in self._records:
            if r.overhead_ms > self._overhead_threshold:
                conflicts.append(
                    {
                        "record_id": r.id,
                        "task_id": r.task_id,
                        "conflict_type": r.conflict_type.value,
                        "coordination_mode": r.coordination_mode.value,
                        "overhead_ms": r.overhead_ms,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(conflicts, key=lambda x: x["overhead_ms"], reverse=True)

    def recommend_coordination_mode(self, task_type: str) -> dict[str, Any]:
        """Suggest best coordination mode based on historical overhead."""
        task_records = [r for r in self._records if r.task_id == task_type]
        if not task_records:
            return {
                "task_type": task_type,
                "recommended_mode": CoordinationMode.SEQUENTIAL.value,
                "reason": "no_history_default",
            }
        mode_overhead: dict[str, list[float]] = {}
        for r in task_records:
            mode_overhead.setdefault(r.coordination_mode.value, []).append(r.overhead_ms)
        mode_avg: dict[str, float] = {}
        for mode, overheads in mode_overhead.items():
            mode_avg[mode] = round(sum(overheads) / len(overheads), 2)
        best_mode = min(mode_avg, key=mode_avg.get)  # type: ignore[arg-type]
        return {
            "task_type": task_type,
            "recommended_mode": best_mode,
            "avg_overhead_ms": mode_avg[best_mode],
            "all_modes": mode_avg,
            "reason": "lowest_avg_overhead",
        }

    def measure_coordination_overhead(self) -> dict[str, Any]:
        """Track overhead of multi-agent coordination by mode."""
        if not self._records:
            return {"total_overhead_ms": 0.0, "by_mode": {}}
        mode_data: dict[str, list[float]] = {}
        for r in self._records:
            mode_data.setdefault(r.coordination_mode.value, []).append(r.overhead_ms)
        by_mode: dict[str, Any] = {}
        total_overhead = 0.0
        for mode, overheads in mode_data.items():
            avg = round(sum(overheads) / len(overheads), 2)
            total = round(sum(overheads), 2)
            by_mode[mode] = {
                "count": len(overheads),
                "avg_overhead_ms": avg,
                "total_overhead_ms": total,
            }
            total_overhead += total
        return {
            "total_overhead_ms": round(total_overhead, 2),
            "by_mode": by_mode,
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> CoordinationReport:
        by_mode: dict[str, int] = {}
        by_conflict: dict[str, int] = {}
        by_resolution: dict[str, int] = {}
        for r in self._records:
            by_mode[r.coordination_mode.value] = by_mode.get(r.coordination_mode.value, 0) + 1
            by_conflict[r.conflict_type.value] = by_conflict.get(r.conflict_type.value, 0) + 1
            by_resolution[r.resolution_strategy.value] = (
                by_resolution.get(r.resolution_strategy.value, 0) + 1
            )
        high_overhead_count = sum(
            1 for r in self._records if r.overhead_ms > self._overhead_threshold
        )
        overheads = [r.overhead_ms for r in self._records]
        avg_overhead_ms = round(sum(overheads) / len(overheads), 2) if overheads else 0.0
        high_list = self.detect_coordination_conflicts()
        top_high_overhead = [o["task_id"] for o in high_list[:5]]
        recs: list[str] = []
        if self._records and high_overhead_count > 0:
            recs.append(
                f"{high_overhead_count} coordination(s) above overhead threshold "
                f"({self._overhead_threshold}ms)"
            )
        if self._records and avg_overhead_ms > self._overhead_threshold:
            recs.append(
                f"Avg coordination overhead {avg_overhead_ms}ms above threshold "
                f"({self._overhead_threshold}ms)"
            )
        if not recs:
            recs.append("Multi-agent coordination overhead is healthy")
        return CoordinationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            high_overhead_count=high_overhead_count,
            avg_overhead_ms=avg_overhead_ms,
            by_mode=by_mode,
            by_conflict=by_conflict,
            by_resolution=by_resolution,
            top_high_overhead=top_high_overhead,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("multi_agent_coordination_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        mode_dist: dict[str, int] = {}
        for r in self._records:
            key = r.coordination_mode.value
            mode_dist[key] = mode_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "overhead_threshold": self._overhead_threshold,
            "mode_distribution": mode_dist,
            "unique_tasks": len({r.task_id for r in self._records}),
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
