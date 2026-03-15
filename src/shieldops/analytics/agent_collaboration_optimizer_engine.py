"""AgentCollaborationOptimizerEngine — Optimize how agents collaborate on complex tasks."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CollaborationMode(StrEnum):
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    CONSENSUS = "consensus"
    HIERARCHICAL = "hierarchical"


class HandoffQuality(StrEnum):
    CLEAN = "clean"
    PARTIAL = "partial"
    FAILED = "failed"
    REDUNDANT = "redundant"


class ConflictType(StrEnum):
    RESOURCE = "resource"
    PRIORITY = "priority"
    DATA = "data"
    DECISION = "decision"


# --- Models ---


class AgentCollaborationOptimizerRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    collaboration_mode: CollaborationMode = CollaborationMode.SEQUENTIAL
    handoff_quality: HandoffQuality = HandoffQuality.CLEAN
    conflict_type: ConflictType = ConflictType.RESOURCE
    score: float = 0.0
    agent_count: int = 0
    latency_ms: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AgentCollaborationOptimizerAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    collaboration_mode: CollaborationMode = CollaborationMode.SEQUENTIAL
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AgentCollaborationOptimizerReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_collaboration_mode: dict[str, int] = Field(default_factory=dict)
    by_handoff_quality: dict[str, int] = Field(default_factory=dict)
    by_conflict_type: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AgentCollaborationOptimizerEngine:
    """Optimize how agents collaborate on complex tasks."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[AgentCollaborationOptimizerRecord] = []
        self._analyses: list[AgentCollaborationOptimizerAnalysis] = []
        logger.info(
            "agent_collaboration_optimizer_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        collaboration_mode: CollaborationMode = CollaborationMode.SEQUENTIAL,
        handoff_quality: HandoffQuality = HandoffQuality.CLEAN,
        conflict_type: ConflictType = ConflictType.RESOURCE,
        score: float = 0.0,
        agent_count: int = 0,
        latency_ms: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> AgentCollaborationOptimizerRecord:
        record = AgentCollaborationOptimizerRecord(
            name=name,
            collaboration_mode=collaboration_mode,
            handoff_quality=handoff_quality,
            conflict_type=conflict_type,
            score=score,
            agent_count=agent_count,
            latency_ms=latency_ms,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "agent_collaboration_optimizer_engine.record_added",
            record_id=record.id,
            name=name,
            collaboration_mode=collaboration_mode.value,
            handoff_quality=handoff_quality.value,
        )
        return record

    def get_record(self, record_id: str) -> AgentCollaborationOptimizerRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        collaboration_mode: CollaborationMode | None = None,
        handoff_quality: HandoffQuality | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[AgentCollaborationOptimizerRecord]:
        results = list(self._records)
        if collaboration_mode is not None:
            results = [r for r in results if r.collaboration_mode == collaboration_mode]
        if handoff_quality is not None:
            results = [r for r in results if r.handoff_quality == handoff_quality]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        collaboration_mode: CollaborationMode = CollaborationMode.SEQUENTIAL,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> AgentCollaborationOptimizerAnalysis:
        analysis = AgentCollaborationOptimizerAnalysis(
            name=name,
            collaboration_mode=collaboration_mode,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "agent_collaboration_optimizer_engine.analysis_added",
            name=name,
            collaboration_mode=collaboration_mode.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def detect_collaboration_bottlenecks(self) -> list[dict[str, Any]]:
        """Detect bottlenecks in agent collaboration patterns."""
        mode_data: dict[str, list[AgentCollaborationOptimizerRecord]] = {}
        for r in self._records:
            mode_data.setdefault(r.collaboration_mode.value, []).append(r)
        bottlenecks: list[dict[str, Any]] = []
        for mode, records in mode_data.items():
            total = len(records)
            failed = sum(1 for r in records if r.handoff_quality == HandoffQuality.FAILED)
            partial = sum(1 for r in records if r.handoff_quality == HandoffQuality.PARTIAL)
            avg_latency = round(sum(r.latency_ms for r in records) / total, 2) if total else 0.0
            failure_rate = round((failed + partial) / total * 100, 1) if total else 0.0
            if failed > 0 or partial > 0:
                bottlenecks.append(
                    {
                        "collaboration_mode": mode,
                        "total_interactions": total,
                        "failed_handoffs": failed,
                        "partial_handoffs": partial,
                        "failure_rate": failure_rate,
                        "avg_latency_ms": avg_latency,
                        "severity": "critical" if failure_rate > 30 else "warning",
                    }
                )
        return sorted(bottlenecks, key=lambda x: x["failure_rate"], reverse=True)

    def optimize_agent_handoffs(self) -> list[dict[str, Any]]:
        """Analyze handoff patterns and suggest optimizations."""
        svc_handoffs: dict[str, list[AgentCollaborationOptimizerRecord]] = {}
        for r in self._records:
            svc_handoffs.setdefault(r.service, []).append(r)
        optimizations: list[dict[str, Any]] = []
        for svc, records in svc_handoffs.items():
            total = len(records)
            clean = sum(1 for r in records if r.handoff_quality == HandoffQuality.CLEAN)
            redundant = sum(1 for r in records if r.handoff_quality == HandoffQuality.REDUNDANT)
            failed = sum(1 for r in records if r.handoff_quality == HandoffQuality.FAILED)
            if failed > 0:
                optimizations.append(
                    {
                        "service": svc,
                        "issue": "failed_handoffs",
                        "count": failed,
                        "total": total,
                        "priority": "critical",
                        "suggestion": f"Fix {failed} failed handoffs in {svc}",
                    }
                )
            if redundant > 0:
                optimizations.append(
                    {
                        "service": svc,
                        "issue": "redundant_handoffs",
                        "count": redundant,
                        "total": total,
                        "priority": "medium",
                        "suggestion": (
                            f"Eliminate {redundant} redundant handoffs "
                            f"({round(redundant / total * 100, 1)}%)"
                        ),
                    }
                )
            if clean == total and total > 0:
                optimizations.append(
                    {
                        "service": svc,
                        "issue": "none",
                        "count": 0,
                        "total": total,
                        "priority": "info",
                        "suggestion": f"All {total} handoffs clean for {svc}",
                    }
                )
        priority_order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
        return sorted(optimizations, key=lambda x: priority_order.get(x["priority"], 4))

    def resolve_agent_conflicts(self) -> list[dict[str, Any]]:
        """Analyze and recommend resolutions for agent conflicts."""
        conflict_data: dict[str, list[AgentCollaborationOptimizerRecord]] = {}
        for r in self._records:
            if r.handoff_quality in (HandoffQuality.FAILED, HandoffQuality.PARTIAL):
                conflict_data.setdefault(r.conflict_type.value, []).append(r)
        resolutions: list[dict[str, Any]] = []
        resolution_map = {
            "resource": "Implement resource locking or queue-based allocation",
            "priority": "Define clear priority hierarchy among agents",
            "data": "Add data validation at handoff boundaries",
            "decision": "Implement consensus protocol for conflicting decisions",
        }
        for conflict, records in conflict_data.items():
            affected_services = sorted({r.service for r in records})
            avg_score = round(sum(r.score for r in records) / len(records), 2) if records else 0.0
            resolutions.append(
                {
                    "conflict_type": conflict,
                    "occurrence_count": len(records),
                    "affected_services": affected_services,
                    "avg_score_impact": avg_score,
                    "resolution": resolution_map.get(conflict, "Review conflict pattern"),
                    "severity": "critical" if len(records) > 5 else "warning",
                }
            )
        return sorted(resolutions, key=lambda x: x["occurrence_count"], reverse=True)

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.collaboration_mode.value
            type_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in type_data.items():
            result[k] = {
                "count": len(scores),
                "avg_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_gaps(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "collaboration_mode": r.collaboration_mode.value,
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc_scores: dict[str, list[float]] = {}
        for r in self._records:
            svc_scores.setdefault(r.service, []).append(r.score)
        results: list[dict[str, Any]] = []
        for svc, scores in svc_scores.items():
            results.append(
                {
                    "service": svc,
                    "avg_score": round(sum(scores) / len(scores), 2),
                }
            )
        results.sort(key=lambda x: x["avg_score"])
        return results

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> AgentCollaborationOptimizerReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.collaboration_mode.value] = by_e1.get(r.collaboration_mode.value, 0) + 1
            by_e2[r.handoff_quality.value] = by_e2.get(r.handoff_quality.value, 0) + 1
            by_e3[r.conflict_type.value] = by_e3.get(r.conflict_type.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("Agent Collaboration Optimizer Engine is healthy")
        return AgentCollaborationOptimizerReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_collaboration_mode=by_e1,
            by_handoff_quality=by_e2,
            by_conflict_type=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("agent_collaboration_optimizer_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.collaboration_mode.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "collaboration_mode_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
