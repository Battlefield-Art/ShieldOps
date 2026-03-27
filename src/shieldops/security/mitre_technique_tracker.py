"""MITRETechniqueTracker -- track MITRE ATT&CK coverage."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class TacticCategory(StrEnum):
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    COMMAND_AND_CONTROL = "command_and_control"
    IMPACT = "impact"


class TechniqueStatus(StrEnum):
    COVERED = "covered"
    PARTIAL = "partial"
    NOT_COVERED = "not_covered"
    PLANNED = "planned"


class DetectionMaturity(StrEnum):
    INITIAL = "initial"
    DEFINED = "defined"
    MANAGED = "managed"
    MEASURED = "measured"
    OPTIMIZED = "optimized"


# --- Models ---


class MITRETechniqueRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    technique_id: str = ""
    tactic: TacticCategory = TacticCategory.INITIAL_ACCESS
    status: TechniqueStatus = TechniqueStatus.NOT_COVERED
    maturity: DetectionMaturity = DetectionMaturity.INITIAL
    score: float = 0.0
    data_source: str = ""
    detection_rule: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class MITRETechniqueAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    tactic: TacticCategory = TacticCategory.INITIAL_ACCESS
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class MITRETechniqueReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_tactic: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    by_maturity: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class MITRETechniqueTracker:
    """Track MITRE ATT&CK technique coverage."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[MITRETechniqueRecord] = []
        self._analyses: list[MITRETechniqueAnalysis] = []
        logger.info(
            "mitre_technique_tracker.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ---

    def add_record(
        self,
        name: str,
        technique_id: str = "",
        tactic: TacticCategory = TacticCategory.INITIAL_ACCESS,
        status: TechniqueStatus = TechniqueStatus.NOT_COVERED,
        maturity: DetectionMaturity = DetectionMaturity.INITIAL,
        score: float = 0.0,
        data_source: str = "",
        detection_rule: str = "",
        service: str = "",
        team: str = "",
    ) -> MITRETechniqueRecord:
        record = MITRETechniqueRecord(
            name=name,
            technique_id=technique_id,
            tactic=tactic,
            status=status,
            maturity=maturity,
            score=score,
            data_source=data_source,
            detection_rule=detection_rule,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "mitre_technique_tracker.record_added",
            record_id=record.id,
            name=name,
            tactic=tactic.value,
        )
        return record

    def get_record(self, record_id: str) -> MITRETechniqueRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        tactic: TacticCategory | None = None,
        status: TechniqueStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[MITRETechniqueRecord]:
        results = list(self._records)
        if tactic is not None:
            results = [r for r in results if r.tactic == tactic]
        if status is not None:
            results = [r for r in results if r.status == status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        tactic: TacticCategory = TacticCategory.INITIAL_ACCESS,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> MITRETechniqueAnalysis:
        analysis = MITRETechniqueAnalysis(
            name=name,
            tactic=tactic,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "mitre_technique_tracker.analysis_added",
            name=name,
            tactic=tactic.value,
        )
        return analysis

    # -- domain operations ---

    def track_technique(self) -> list[dict[str, Any]]:
        """Track techniques by tactic and status."""
        tactic_data: dict[str, list[MITRETechniqueRecord]] = {}
        for r in self._records:
            tactic_data.setdefault(r.tactic.value, []).append(r)
        results: list[dict[str, Any]] = []
        for tactic, records in tactic_data.items():
            covered = sum(1 for r in records if r.status == TechniqueStatus.COVERED)
            total = len(records)
            pct = round(covered / total * 100, 1)
            results.append(
                {
                    "tactic": tactic,
                    "total": total,
                    "covered": covered,
                    "coverage_pct": pct,
                }
            )
        return sorted(results, key=lambda x: x["coverage_pct"])

    def calculate_tactic_coverage(
        self,
    ) -> dict[str, Any]:
        """Calculate coverage per tactic category."""
        tactic_scores: dict[str, list[float]] = {}
        for r in self._records:
            tactic_scores.setdefault(r.tactic.value, []).append(r.score)
        coverage: dict[str, Any] = {}
        for tactic, scores in tactic_scores.items():
            avg = sum(scores) / len(scores)
            coverage[tactic] = {
                "avg_score": round(avg, 2),
                "count": len(scores),
                "above_threshold_pct": round(
                    sum(1 for s in scores if s >= self._threshold) / len(scores) * 100,
                    1,
                ),
            }
        return coverage

    def identify_priority_gaps(
        self,
    ) -> list[dict[str, Any]]:
        """Identify high-priority coverage gaps."""
        gaps: list[dict[str, Any]] = []
        for r in self._records:
            if r.status == TechniqueStatus.NOT_COVERED:
                gaps.append(
                    {
                        "technique_id": r.technique_id,
                        "name": r.name,
                        "tactic": r.tactic.value,
                        "score": r.score,
                        "maturity": r.maturity.value,
                    }
                )
        return sorted(gaps, key=lambda x: x["score"])

    # -- standard methods ---

    def analyze_distribution(
        self,
    ) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.tactic.value
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
                        "tactic": r.tactic.value,
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
        matched = [r for r in self._records if r.name == key or r.technique_id == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats ---

    def generate_report(self) -> MITRETechniqueReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            v1 = r.tactic.value
            by_e1[v1] = by_e1.get(v1, 0) + 1
            v2 = r.status.value
            by_e2[v2] = by_e2.get(v2, 0) + 1
            v3 = r.maturity.value
            by_e3[v3] = by_e3.get(v3, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg < self._threshold:
            recs.append(f"Avg score {avg} below threshold ({self._threshold})")
        if not recs:
            recs.append("MITRE Technique Tracker is healthy")
        return MITRETechniqueReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg,
            by_tactic=by_e1,
            by_status=by_e2,
            by_maturity=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("mitre_technique_tracker.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.tactic.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "tactic_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
