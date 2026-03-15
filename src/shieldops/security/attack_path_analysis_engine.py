"""AttackPathAnalysisEngine — Analyze potential attack paths through infrastructure."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PathComplexity(StrEnum):
    TRIVIAL = "trivial"
    MODERATE = "moderate"
    COMPLEX = "complex"
    THEORETICAL = "theoretical"


class PathStatus(StrEnum):
    ACTIVE = "active"
    BLOCKED = "blocked"
    PARTIALLY_BLOCKED = "partially_blocked"


class EntryPointType(StrEnum):
    EXTERNAL = "external"
    INTERNAL = "internal"
    SUPPLY_CHAIN = "supply_chain"


# --- Models ---


class AttackPathAnalysisRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    complexity: PathComplexity = PathComplexity.MODERATE
    status: PathStatus = PathStatus.ACTIVE
    entry_point: EntryPointType = EntryPointType.EXTERNAL
    score: float = 0.0
    path_length: int = 0
    risk_score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AttackPathAnalysisAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    complexity: PathComplexity = PathComplexity.MODERATE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AttackPathAnalysisReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_complexity: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    by_entry_point: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AttackPathAnalysisEngine:
    """Analyze and track potential attack paths through infrastructure."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[AttackPathAnalysisRecord] = []
        self._analyses: list[AttackPathAnalysisAnalysis] = []
        logger.info(
            "attack_path_analysis_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        complexity: PathComplexity = PathComplexity.MODERATE,
        status: PathStatus = PathStatus.ACTIVE,
        entry_point: EntryPointType = EntryPointType.EXTERNAL,
        score: float = 0.0,
        path_length: int = 0,
        risk_score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> AttackPathAnalysisRecord:
        record = AttackPathAnalysisRecord(
            name=name,
            complexity=complexity,
            status=status,
            entry_point=entry_point,
            score=score,
            path_length=path_length,
            risk_score=risk_score,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "attack_path_analysis_engine.record_added",
            record_id=record.id,
            name=name,
            complexity=complexity.value,
            status=status.value,
        )
        return record

    def get_record(self, record_id: str) -> AttackPathAnalysisRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        complexity: PathComplexity | None = None,
        status: PathStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[AttackPathAnalysisRecord]:
        results = list(self._records)
        if complexity is not None:
            results = [r for r in results if r.complexity == complexity]
        if status is not None:
            results = [r for r in results if r.status == status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        complexity: PathComplexity = PathComplexity.MODERATE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> AttackPathAnalysisAnalysis:
        analysis = AttackPathAnalysisAnalysis(
            name=name,
            complexity=complexity,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "attack_path_analysis_engine.analysis_added",
            name=name,
            complexity=complexity.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def identify_shortest_attack_paths(self) -> list[dict[str, Any]]:
        """Identify shortest (easiest) attack paths by path length and complexity."""
        active_paths = [r for r in self._records if r.status == PathStatus.ACTIVE]
        results: list[dict[str, Any]] = []
        for r in active_paths:
            complexity_weight = {
                PathComplexity.TRIVIAL: 1.0,
                PathComplexity.MODERATE: 2.0,
                PathComplexity.COMPLEX: 3.0,
                PathComplexity.THEORETICAL: 4.0,
            }
            effective_length = r.path_length * complexity_weight.get(r.complexity, 2.0)
            results.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "path_length": r.path_length,
                    "complexity": r.complexity.value,
                    "effective_length": effective_length,
                    "risk_score": r.risk_score,
                    "entry_point": r.entry_point.value,
                    "priority": "critical"
                    if effective_length <= 2
                    else "high"
                    if effective_length <= 4
                    else "medium"
                    if effective_length <= 8
                    else "low",
                }
            )
        return sorted(results, key=lambda x: x["effective_length"])

    def evaluate_path_blockage(self) -> list[dict[str, Any]]:
        """Evaluate how well attack paths are blocked per service."""
        svc_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, {})
            st = r.status.value
            svc_data[r.service][st] = svc_data[r.service].get(st, 0) + 1
        results: list[dict[str, Any]] = []
        for svc, statuses in svc_data.items():
            total = sum(statuses.values())
            blocked = statuses.get("blocked", 0)
            blockage_pct = round(blocked / total * 100, 1) if total > 0 else 0.0
            results.append(
                {
                    "service": svc,
                    "total_paths": total,
                    "blocked": blocked,
                    "partially_blocked": statuses.get("partially_blocked", 0),
                    "active": statuses.get("active", 0),
                    "blockage_pct": blockage_pct,
                    "grade": "excellent"
                    if blockage_pct >= 90
                    else "good"
                    if blockage_pct >= 70
                    else "fair"
                    if blockage_pct >= 50
                    else "poor",
                }
            )
        return sorted(results, key=lambda x: x["blockage_pct"])

    def recommend_choke_points(self) -> list[dict[str, Any]]:
        """Recommend choke points to block the most attack paths."""
        recommendations: list[dict[str, Any]] = []
        active = [r for r in self._records if r.status == PathStatus.ACTIVE]
        svc_active: dict[str, list[AttackPathAnalysisRecord]] = {}
        for r in active:
            svc_active.setdefault(r.service, []).append(r)
        for svc, records in svc_active.items():
            avg_risk = round(sum(r.risk_score for r in records) / len(records), 2)
            trivial_count = sum(1 for r in records if r.complexity == PathComplexity.TRIVIAL)
            recommendations.append(
                {
                    "service": svc,
                    "active_paths": len(records),
                    "avg_risk_score": avg_risk,
                    "trivial_paths": trivial_count,
                    "priority": "critical"
                    if trivial_count > 0
                    else "high"
                    if avg_risk > 7
                    else "medium"
                    if avg_risk > 4
                    else "low",
                    "suggestion": f"Block {len(records)} active paths in {svc} "
                    f"(avg risk: {avg_risk})",
                }
            )
        return sorted(
            recommendations,
            key=lambda x: (
                0
                if x["priority"] == "critical"
                else 1
                if x["priority"] == "high"
                else 2
                if x["priority"] == "medium"
                else 3
            ),
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.complexity.value
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
                        "complexity": r.complexity.value,
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

    def generate_report(self) -> AttackPathAnalysisReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.complexity.value] = by_e1.get(r.complexity.value, 0) + 1
            by_e2[r.status.value] = by_e2.get(r.status.value, 0) + 1
            by_e3[r.entry_point.value] = by_e3.get(r.entry_point.value, 0) + 1
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
            recs.append("Attack Path Analysis Engine is healthy")
        return AttackPathAnalysisReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_complexity=by_e1,
            by_status=by_e2,
            by_entry_point=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("attack_path_analysis_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.complexity.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "complexity_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
