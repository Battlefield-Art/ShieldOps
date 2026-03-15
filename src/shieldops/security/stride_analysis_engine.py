"""StrideAnalysisEngine — Track STRIDE threat analysis results and trends."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class StrideCategory(StrEnum):
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFO_DISCLOSURE = "info_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION = "elevation"


class ThreatStatus(StrEnum):
    IDENTIFIED = "identified"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted"
    MONITORING = "monitoring"


class AnalysisDepth(StrEnum):
    SURFACE = "surface"
    STANDARD = "standard"
    DEEP = "deep"


# --- Models ---


class StrideAnalysisRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    category: StrideCategory = StrideCategory.SPOOFING
    status: ThreatStatus = ThreatStatus.IDENTIFIED
    depth: AnalysisDepth = AnalysisDepth.STANDARD
    score: float = 0.0
    threat_count: int = 0
    severity_score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class StrideAnalysisAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    category: StrideCategory = StrideCategory.SPOOFING
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class StrideAnalysisReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_category: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    by_depth: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class StrideAnalysisEngine:
    """Track STRIDE threat analysis results and trends."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[StrideAnalysisRecord] = []
        self._analyses: list[StrideAnalysisAnalysis] = []
        logger.info(
            "stride_analysis_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        category: StrideCategory = StrideCategory.SPOOFING,
        status: ThreatStatus = ThreatStatus.IDENTIFIED,
        depth: AnalysisDepth = AnalysisDepth.STANDARD,
        score: float = 0.0,
        threat_count: int = 0,
        severity_score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> StrideAnalysisRecord:
        record = StrideAnalysisRecord(
            name=name,
            category=category,
            status=status,
            depth=depth,
            score=score,
            threat_count=threat_count,
            severity_score=severity_score,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "stride_analysis_engine.record_added",
            record_id=record.id,
            name=name,
            category=category.value,
            status=status.value,
        )
        return record

    def get_record(self, record_id: str) -> StrideAnalysisRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        category: StrideCategory | None = None,
        status: ThreatStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[StrideAnalysisRecord]:
        results = list(self._records)
        if category is not None:
            results = [r for r in results if r.category == category]
        if status is not None:
            results = [r for r in results if r.status == status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        category: StrideCategory = StrideCategory.SPOOFING,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> StrideAnalysisAnalysis:
        analysis = StrideAnalysisAnalysis(
            name=name,
            category=category,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "stride_analysis_engine.analysis_added",
            name=name,
            category=category.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def compute_threat_density(self) -> list[dict[str, Any]]:
        """Compute threat density per service across STRIDE categories."""
        svc_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, {})
            cat = r.category.value
            svc_data[r.service][cat] = svc_data[r.service].get(cat, 0) + r.threat_count
        results: list[dict[str, Any]] = []
        for svc, cats in svc_data.items():
            total = sum(cats.values())
            results.append(
                {
                    "service": svc,
                    "total_threats": total,
                    "by_category": cats,
                    "density_grade": "critical"
                    if total > 20
                    else "high"
                    if total > 10
                    else "medium"
                    if total > 5
                    else "low",
                }
            )
        return sorted(results, key=lambda x: x["total_threats"], reverse=True)

    def identify_unmitigated_threats(self) -> list[dict[str, Any]]:
        """Identify threats that are not yet mitigated."""
        unmitigated: list[dict[str, Any]] = []
        for r in self._records:
            if r.status == ThreatStatus.IDENTIFIED:
                unmitigated.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "service": r.service,
                        "category": r.category.value,
                        "severity_score": r.severity_score,
                        "threat_count": r.threat_count,
                        "priority": "critical"
                        if r.severity_score > 8
                        else "high"
                        if r.severity_score > 6
                        else "medium"
                        if r.severity_score > 4
                        else "low",
                    }
                )
        return sorted(unmitigated, key=lambda x: x["severity_score"], reverse=True)

    def recommend_analysis_priorities(self) -> list[dict[str, Any]]:
        """Recommend which services need deeper analysis."""
        recommendations: list[dict[str, Any]] = []
        svc_depth: dict[str, list[StrideAnalysisRecord]] = {}
        for r in self._records:
            svc_depth.setdefault(r.service, []).append(r)
        for svc, records in svc_depth.items():
            surface_only = all(r.depth == AnalysisDepth.SURFACE for r in records)
            has_identified = any(r.status == ThreatStatus.IDENTIFIED for r in records)
            avg_severity = round(sum(r.severity_score for r in records) / len(records), 2)
            if surface_only and has_identified:
                recommendations.append(
                    {
                        "service": svc,
                        "issue": "surface_only_analysis",
                        "avg_severity": avg_severity,
                        "record_count": len(records),
                        "priority": "high",
                        "suggestion": f"Deepen analysis for {svc} (only surface-level done)",
                    }
                )
            elif has_identified and avg_severity > 5:
                recommendations.append(
                    {
                        "service": svc,
                        "issue": "high_severity_unmitigated",
                        "avg_severity": avg_severity,
                        "record_count": len(records),
                        "priority": "high",
                        "suggestion": (
                            f"Prioritize mitigation for {svc} (avg severity: {avg_severity})"
                        ),
                    }
                )
        return sorted(
            recommendations,
            key=lambda x: 0 if x["priority"] == "high" else 1 if x["priority"] == "medium" else 2,
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.category.value
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
                        "category": r.category.value,
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

    def generate_report(self) -> StrideAnalysisReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.category.value] = by_e1.get(r.category.value, 0) + 1
            by_e2[r.status.value] = by_e2.get(r.status.value, 0) + 1
            by_e3[r.depth.value] = by_e3.get(r.depth.value, 0) + 1
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
            recs.append("STRIDE Analysis Engine is healthy")
        return StrideAnalysisReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_category=by_e1,
            by_status=by_e2,
            by_depth=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("stride_analysis_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.category.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "category_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
