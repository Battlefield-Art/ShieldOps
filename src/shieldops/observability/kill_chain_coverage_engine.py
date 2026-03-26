"""KillChainCoverageEngine — Track detection coverage across kill chain phases."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class KillChainPhase(StrEnum):
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    LATERAL_MOVEMENT = "lateral_movement"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class DetectionCoverage(StrEnum):
    FULL = "full"
    PARTIAL = "partial"
    NONE = "none"
    ALERT_ONLY = "alert_only"
    LOG_ONLY = "log_only"


class CoverageGap(StrEnum):
    NO_DETECTION = "no_detection"
    NO_PREVENTION = "no_prevention"
    NO_RESPONSE = "no_response"
    DELAYED_DETECTION = "delayed_detection"
    BLIND_SPOT = "blind_spot"


# --- Models ---


class KillChainCoverageRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    kill_chain_phase: KillChainPhase = KillChainPhase.RECONNAISSANCE
    detection_coverage: DetectionCoverage = DetectionCoverage.FULL
    coverage_gap: CoverageGap = CoverageGap.NO_DETECTION
    score: float = 0.0
    detection_count: int = 0
    technique_id: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class KillChainCoverageAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    kill_chain_phase: KillChainPhase = KillChainPhase.RECONNAISSANCE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class KillChainCoverageReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_kill_chain_phase: dict[str, int] = Field(default_factory=dict)
    by_detection_coverage: dict[str, int] = Field(default_factory=dict)
    by_coverage_gap: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class KillChainCoverageEngine:
    """Track detection coverage across kill chain phases."""

    def __init__(
        self,
        max_records: int = 200000,
        coverage_threshold: float = 80.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = coverage_threshold
        self._records: list[KillChainCoverageRecord] = []
        self._analyses: list[KillChainCoverageAnalysis] = []
        logger.info(
            "kill_chain_coverage_engine.initialized",
            max_records=max_records,
            coverage_threshold=coverage_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        kill_chain_phase: KillChainPhase = KillChainPhase.RECONNAISSANCE,
        detection_coverage: DetectionCoverage = DetectionCoverage.FULL,
        coverage_gap: CoverageGap = CoverageGap.NO_DETECTION,
        score: float = 0.0,
        detection_count: int = 0,
        technique_id: str = "",
        service: str = "",
        team: str = "",
    ) -> KillChainCoverageRecord:
        record = KillChainCoverageRecord(
            name=name,
            kill_chain_phase=kill_chain_phase,
            detection_coverage=detection_coverage,
            coverage_gap=coverage_gap,
            score=score,
            detection_count=detection_count,
            technique_id=technique_id,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "kill_chain_coverage_engine.record_added",
            record_id=record.id,
            name=name,
            kill_chain_phase=kill_chain_phase.value,
            detection_coverage=detection_coverage.value,
        )
        return record

    def get_record(self, record_id: str) -> KillChainCoverageRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        kill_chain_phase: KillChainPhase | None = None,
        detection_coverage: DetectionCoverage | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[KillChainCoverageRecord]:
        results = list(self._records)
        if kill_chain_phase is not None:
            results = [
                r for r in results if r.kill_chain_phase == kill_chain_phase
            ]
        if detection_coverage is not None:
            results = [
                r for r in results if r.detection_coverage == detection_coverage
            ]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        kill_chain_phase: KillChainPhase = KillChainPhase.RECONNAISSANCE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> KillChainCoverageAnalysis:
        analysis = KillChainCoverageAnalysis(
            name=name,
            kill_chain_phase=kill_chain_phase,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "kill_chain_coverage_engine.analysis_added",
            name=name,
            kill_chain_phase=kill_chain_phase.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def identify_coverage_blind_spots(self) -> list[dict[str, Any]]:
        """Identify kill chain phases with detection blind spots."""
        phase_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            p = r.kill_chain_phase.value
            phase_data.setdefault(p, {})
            c = r.detection_coverage.value
            phase_data[p][c] = phase_data[p].get(c, 0) + 1
        blind_spots: list[dict[str, Any]] = []
        for phase, coverages in phase_data.items():
            total = sum(coverages.values())
            no_coverage = coverages.get("none", 0)
            partial = coverages.get("partial", 0)
            gap_pct = (
                round((no_coverage + partial) / total * 100, 1)
                if total
                else 0.0
            )
            if no_coverage > 0 or partial > 0:
                blind_spots.append(
                    {
                        "phase": phase,
                        "total_techniques": total,
                        "no_coverage": no_coverage,
                        "partial_coverage": partial,
                        "gap_pct": gap_pct,
                        "severity": (
                            "critical" if no_coverage > partial else "warning"
                        ),
                    }
                )
        return sorted(blind_spots, key=lambda x: x["gap_pct"], reverse=True)

    def compute_phase_coverage(self) -> list[dict[str, Any]]:
        """Compute detection coverage per kill chain phase."""
        phase_records: dict[str, list[KillChainCoverageRecord]] = {}
        for r in self._records:
            phase_records.setdefault(r.kill_chain_phase.value, []).append(r)
        results: list[dict[str, Any]] = []
        for phase, records in phase_records.items():
            total = len(records)
            covered = sum(
                1
                for r in records
                if r.detection_coverage
                in (DetectionCoverage.FULL, DetectionCoverage.ALERT_ONLY)
            )
            coverage = round(covered / total * 100, 1) if total else 0.0
            avg_score = (
                round(sum(r.score for r in records) / total, 2)
                if total
                else 0.0
            )
            results.append(
                {
                    "phase": phase,
                    "total_techniques": total,
                    "covered": covered,
                    "coverage_pct": coverage,
                    "avg_score": avg_score,
                }
            )
        return sorted(results, key=lambda x: x["coverage_pct"])

    def recommend_detection_additions(self) -> list[dict[str, Any]]:
        """Recommend detection additions for uncovered techniques."""
        recommendations: list[dict[str, Any]] = []
        no_detect = [
            r
            for r in self._records
            if r.detection_coverage == DetectionCoverage.NONE
        ]
        for r in no_detect:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "phase": r.kill_chain_phase.value,
                    "issue": "no_detection",
                    "priority": "critical",
                    "suggestion": (
                        f"Create detection for {r.technique_id or r.name} "
                        f"({r.kill_chain_phase.value})"
                    ),
                }
            )
        log_only = [
            r
            for r in self._records
            if r.detection_coverage == DetectionCoverage.LOG_ONLY
        ]
        for r in log_only:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "phase": r.kill_chain_phase.value,
                    "issue": "log_only",
                    "priority": "high",
                    "suggestion": (
                        f"Add alerting for {r.technique_id or r.name} "
                        f"— currently log-only"
                    ),
                }
            )
        partial = [
            r
            for r in self._records
            if r.detection_coverage == DetectionCoverage.PARTIAL
        ]
        for r in partial:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "phase": r.kill_chain_phase.value,
                    "issue": "partial_coverage",
                    "priority": "medium",
                    "suggestion": (
                        f"Improve coverage for {r.technique_id or r.name}"
                    ),
                }
            )
        priority_order = {"critical": 0, "high": 1, "medium": 2}
        return sorted(
            recommendations, key=lambda x: priority_order.get(x["priority"], 3)
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        phase_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.kill_chain_phase.value
            phase_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in phase_data.items():
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
                        "kill_chain_phase": r.kill_chain_phase.value,
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
        matched = [
            r for r in self._records if r.name == key or r.service == key
        ]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(
                1 for s in scores if s < self._threshold
            ),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> KillChainCoverageReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.kill_chain_phase.value] = (
                by_e1.get(r.kill_chain_phase.value, 0) + 1
            )
            by_e2[r.detection_coverage.value] = (
                by_e2.get(r.detection_coverage.value, 0) + 1
            )
            by_e3[r.coverage_gap.value] = (
                by_e3.get(r.coverage_gap.value, 0) + 1
            )
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(
                f"{gap_count} item(s) below threshold ({self._threshold})"
            )
        if self._records and avg_score < self._threshold:
            recs.append(
                f"Avg score {avg_score} below threshold ({self._threshold})"
            )
        if not recs:
            recs.append("Kill Chain Coverage Engine is healthy")
        return KillChainCoverageReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_kill_chain_phase=by_e1,
            by_detection_coverage=by_e2,
            by_coverage_gap=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("kill_chain_coverage_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.kill_chain_phase.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "kill_chain_phase_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
