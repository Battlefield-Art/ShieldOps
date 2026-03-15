"""InvestigationPatternEngine — Learn recurring investigation patterns for faster resolution."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PatternType(StrEnum):
    SYMPTOM_CLUSTER = "symptom_cluster"
    ROOT_CAUSE_SIGNATURE = "root_cause_signature"
    RESOLUTION_TEMPLATE = "resolution_template"


class PatternConfidence(StrEnum):
    VALIDATED = "validated"
    EMERGING = "emerging"
    SPECULATIVE = "speculative"


class MatchQuality(StrEnum):
    EXACT = "exact"
    SIMILAR = "similar"
    PARTIAL = "partial"


# --- Models ---


class InvestigationPatternRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    pattern_type: PatternType = PatternType.SYMPTOM_CLUSTER
    pattern_confidence: PatternConfidence = PatternConfidence.EMERGING
    match_quality: MatchQuality = MatchQuality.SIMILAR
    score: float = 0.0
    match_count: int = 0
    pattern_hash: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class InvestigationPatternAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    pattern_type: PatternType = PatternType.SYMPTOM_CLUSTER
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class InvestigationPatternReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_pattern_type: dict[str, int] = Field(default_factory=dict)
    by_pattern_confidence: dict[str, int] = Field(default_factory=dict)
    by_match_quality: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class InvestigationPatternEngine:
    """Learn recurring investigation patterns for faster future resolution."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[InvestigationPatternRecord] = []
        self._analyses: list[InvestigationPatternAnalysis] = []
        logger.info(
            "investigation_pattern_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        pattern_type: PatternType = PatternType.SYMPTOM_CLUSTER,
        pattern_confidence: PatternConfidence = PatternConfidence.EMERGING,
        match_quality: MatchQuality = MatchQuality.SIMILAR,
        score: float = 0.0,
        match_count: int = 0,
        pattern_hash: str = "",
        service: str = "",
        team: str = "",
    ) -> InvestigationPatternRecord:
        record = InvestigationPatternRecord(
            name=name,
            pattern_type=pattern_type,
            pattern_confidence=pattern_confidence,
            match_quality=match_quality,
            score=score,
            match_count=match_count,
            pattern_hash=pattern_hash,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "investigation_pattern_engine.record_added",
            record_id=record.id,
            name=name,
            pattern_type=pattern_type.value,
            pattern_confidence=pattern_confidence.value,
        )
        return record

    def get_record(self, record_id: str) -> InvestigationPatternRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        pattern_type: PatternType | None = None,
        pattern_confidence: PatternConfidence | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[InvestigationPatternRecord]:
        results = list(self._records)
        if pattern_type is not None:
            results = [r for r in results if r.pattern_type == pattern_type]
        if pattern_confidence is not None:
            results = [r for r in results if r.pattern_confidence == pattern_confidence]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        pattern_type: PatternType = PatternType.SYMPTOM_CLUSTER,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> InvestigationPatternAnalysis:
        analysis = InvestigationPatternAnalysis(
            name=name,
            pattern_type=pattern_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "investigation_pattern_engine.analysis_added",
            name=name,
            pattern_type=pattern_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def extract_investigation_patterns(self) -> list[dict[str, Any]]:
        """Extract recurring investigation patterns from recorded data."""
        hash_groups: dict[str, list[InvestigationPatternRecord]] = {}
        for r in self._records:
            if r.pattern_hash:
                hash_groups.setdefault(r.pattern_hash, []).append(r)
        patterns: list[dict[str, Any]] = []
        for pattern_hash, records in hash_groups.items():
            occurrences = len(records)
            if occurrences >= 2:
                avg_score = round(sum(r.score for r in records) / occurrences, 2)
                patterns.append(
                    {
                        "pattern_hash": pattern_hash,
                        "pattern_name": records[0].name,
                        "pattern_type": records[0].pattern_type.value,
                        "occurrences": occurrences,
                        "avg_score": avg_score,
                        "services": sorted({r.service for r in records}),
                        "confidence": (
                            "validated"
                            if occurrences >= 5
                            else "emerging"
                            if occurrences >= 2
                            else "speculative"
                        ),
                    }
                )
        return sorted(patterns, key=lambda x: x["occurrences"], reverse=True)

    def match_incident_to_pattern(self) -> list[dict[str, Any]]:
        """Match current incidents to known patterns."""
        matches: list[dict[str, Any]] = []
        validated = [
            r for r in self._records if r.pattern_confidence == PatternConfidence.VALIDATED
        ]
        non_validated = [
            r for r in self._records if r.pattern_confidence != PatternConfidence.VALIDATED
        ]
        for incident in non_validated:
            for pattern in validated:
                if incident.pattern_hash == pattern.pattern_hash and incident.pattern_hash:
                    matches.append(
                        {
                            "incident_id": incident.id,
                            "incident_name": incident.name,
                            "pattern_id": pattern.id,
                            "pattern_name": pattern.name,
                            "match_quality": incident.match_quality.value,
                            "pattern_type": pattern.pattern_type.value,
                            "service": incident.service,
                        }
                    )
        return matches

    def compute_pattern_accuracy(self) -> list[dict[str, Any]]:
        """Compute accuracy of pattern matching per pattern type."""
        type_data: dict[str, list[InvestigationPatternRecord]] = {}
        for r in self._records:
            type_data.setdefault(r.pattern_type.value, []).append(r)
        results: list[dict[str, Any]] = []
        for ptype, records in type_data.items():
            exact = sum(1 for r in records if r.match_quality == MatchQuality.EXACT)
            total = len(records)
            accuracy = round(exact / total * 100, 1) if total else 0.0
            results.append(
                {
                    "pattern_type": ptype,
                    "total_matches": total,
                    "exact_matches": exact,
                    "accuracy_pct": accuracy,
                    "avg_score": round(sum(r.score for r in records) / total, 2),
                }
            )
        return sorted(results, key=lambda x: x["accuracy_pct"], reverse=True)

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.pattern_type.value
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
                        "pattern_type": r.pattern_type.value,
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

    def generate_report(self) -> InvestigationPatternReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.pattern_type.value] = by_e1.get(r.pattern_type.value, 0) + 1
            by_e2[r.pattern_confidence.value] = by_e2.get(r.pattern_confidence.value, 0) + 1
            by_e3[r.match_quality.value] = by_e3.get(r.match_quality.value, 0) + 1
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
            recs.append("Investigation Pattern Engine is healthy")
        return InvestigationPatternReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_pattern_type=by_e1,
            by_pattern_confidence=by_e2,
            by_match_quality=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("investigation_pattern_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.pattern_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "pattern_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
