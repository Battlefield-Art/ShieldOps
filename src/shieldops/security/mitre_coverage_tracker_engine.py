"""MitreCoverageTrackerEngine — Track MITRE ATT&CK detection coverage over time."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CoverageLevel(StrEnum):
    NONE = "none"
    BASIC = "basic"
    MODERATE = "moderate"
    COMPREHENSIVE = "comprehensive"


class TacticPriority(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CoverageChange(StrEnum):
    IMPROVED = "improved"
    UNCHANGED = "unchanged"
    DEGRADED = "degraded"


# --- Models ---


class MitreCoverageTrackerRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    coverage_level: CoverageLevel = CoverageLevel.NONE
    tactic_priority: TacticPriority = TacticPriority.MEDIUM
    coverage_change: CoverageChange = CoverageChange.UNCHANGED
    score: float = 0.0
    tactic_id: str = ""
    technique_count: int = 0
    covered_techniques: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class MitreCoverageTrackerAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    coverage_level: CoverageLevel = CoverageLevel.NONE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class MitreCoverageTrackerReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_coverage_level: dict[str, int] = Field(default_factory=dict)
    by_tactic_priority: dict[str, int] = Field(default_factory=dict)
    by_coverage_change: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class MitreCoverageTrackerEngine:
    """Track MITRE ATT&CK detection coverage over time engine."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[MitreCoverageTrackerRecord] = []
        self._analyses: list[MitreCoverageTrackerAnalysis] = []
        logger.info(
            "mitre_coverage_tracker_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        coverage_level: CoverageLevel = CoverageLevel.NONE,
        tactic_priority: TacticPriority = TacticPriority.MEDIUM,
        coverage_change: CoverageChange = CoverageChange.UNCHANGED,
        score: float = 0.0,
        tactic_id: str = "",
        technique_count: int = 0,
        covered_techniques: int = 0,
        service: str = "",
        team: str = "",
    ) -> MitreCoverageTrackerRecord:
        record = MitreCoverageTrackerRecord(
            name=name,
            coverage_level=coverage_level,
            tactic_priority=tactic_priority,
            coverage_change=coverage_change,
            score=score,
            tactic_id=tactic_id,
            technique_count=technique_count,
            covered_techniques=covered_techniques,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "mitre_coverage_tracker_engine.record_added",
            record_id=record.id,
            name=name,
            coverage_level=coverage_level.value,
            tactic_priority=tactic_priority.value,
        )
        return record

    def get_record(self, record_id: str) -> MitreCoverageTrackerRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        coverage_level: CoverageLevel | None = None,
        tactic_priority: TacticPriority | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[MitreCoverageTrackerRecord]:
        results = list(self._records)
        if coverage_level is not None:
            results = [r for r in results if r.coverage_level == coverage_level]
        if tactic_priority is not None:
            results = [r for r in results if r.tactic_priority == tactic_priority]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        coverage_level: CoverageLevel = CoverageLevel.NONE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> MitreCoverageTrackerAnalysis:
        analysis = MitreCoverageTrackerAnalysis(
            name=name,
            coverage_level=coverage_level,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "mitre_coverage_tracker_engine.analysis_added",
            name=name,
            coverage_level=coverage_level.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def compute_tactic_coverage(self) -> list[dict[str, Any]]:
        """Compute coverage percentage per MITRE tactic."""
        tactic_data: dict[str, list[MitreCoverageTrackerRecord]] = {}
        for r in self._records:
            tactic_data.setdefault(r.tactic_id, []).append(r)
        results: list[dict[str, Any]] = []
        for tactic_id, records in tactic_data.items():
            total_techniques = sum(r.technique_count for r in records)
            total_covered = sum(r.covered_techniques for r in records)
            coverage_pct = (
                round(total_covered / total_techniques * 100, 1) if total_techniques > 0 else 0.0
            )
            avg_score = round(sum(r.score for r in records) / len(records), 2)
            results.append(
                {
                    "tactic_id": tactic_id,
                    "total_techniques": total_techniques,
                    "covered_techniques": total_covered,
                    "coverage_pct": coverage_pct,
                    "avg_score": avg_score,
                    "record_count": len(records),
                }
            )
        return sorted(results, key=lambda x: x["coverage_pct"])

    def identify_coverage_regressions(self) -> list[dict[str, Any]]:
        """Identify tactics where coverage has degraded."""
        regressions: list[dict[str, Any]] = []
        for r in self._records:
            if r.coverage_change == CoverageChange.DEGRADED:
                regressions.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "tactic_id": r.tactic_id,
                        "service": r.service,
                        "team": r.team,
                        "coverage_level": r.coverage_level.value,
                        "tactic_priority": r.tactic_priority.value,
                        "severity": (
                            "critical"
                            if r.tactic_priority == TacticPriority.CRITICAL
                            else "high"
                            if r.tactic_priority == TacticPriority.HIGH
                            else "medium"
                        ),
                    }
                )
        return sorted(
            regressions,
            key=lambda x: 0 if x["severity"] == "critical" else 1 if x["severity"] == "high" else 2,
        )

    def prioritize_coverage_investments(self) -> list[dict[str, Any]]:
        """Prioritize where to invest in improving detection coverage."""
        tactic_data: dict[str, list[MitreCoverageTrackerRecord]] = {}
        for r in self._records:
            tactic_data.setdefault(r.tactic_id, []).append(r)
        investments: list[dict[str, Any]] = []
        for tactic_id, records in tactic_data.items():
            total_techniques = sum(r.technique_count for r in records)
            total_covered = sum(r.covered_techniques for r in records)
            gap = total_techniques - total_covered
            if gap <= 0:
                continue
            priority_weights = {
                TacticPriority.CRITICAL: 4,
                TacticPriority.HIGH: 3,
                TacticPriority.MEDIUM: 2,
                TacticPriority.LOW: 1,
            }
            max_priority = max(records, key=lambda r: priority_weights[r.tactic_priority])
            investment_score = gap * priority_weights[max_priority.tactic_priority]
            investments.append(
                {
                    "tactic_id": tactic_id,
                    "uncovered_techniques": gap,
                    "total_techniques": total_techniques,
                    "highest_priority": max_priority.tactic_priority.value,
                    "investment_score": investment_score,
                    "recommendation": f"Add {gap} detection rules for {tactic_id}",
                }
            )
        return sorted(investments, key=lambda x: x["investment_score"], reverse=True)

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.coverage_level.value
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
                        "coverage_level": r.coverage_level.value,
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

    def generate_report(self) -> MitreCoverageTrackerReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.coverage_level.value] = by_e1.get(r.coverage_level.value, 0) + 1
            by_e2[r.tactic_priority.value] = by_e2.get(r.tactic_priority.value, 0) + 1
            by_e3[r.coverage_change.value] = by_e3.get(r.coverage_change.value, 0) + 1
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
            recs.append("MITRE Coverage Tracker Engine is healthy")
        return MitreCoverageTrackerReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_coverage_level=by_e1,
            by_tactic_priority=by_e2,
            by_coverage_change=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("mitre_coverage_tracker_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.coverage_level.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "coverage_level_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
