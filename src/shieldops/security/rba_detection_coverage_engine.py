"""RBA Detection Coverage Engine —
map detection coverage to MITRE matrix, prioritize coverage gaps,
estimate detection development effort."""

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
    FULL_COVERAGE = "full_coverage"
    PARTIAL_COVERAGE = "partial_coverage"
    MINIMAL_COVERAGE = "minimal_coverage"
    NO_COVERAGE = "no_coverage"


class GapPriority(StrEnum):
    CRITICAL_GAP = "critical_gap"
    HIGH_GAP = "high_gap"
    MEDIUM_GAP = "medium_gap"
    LOW_GAP = "low_gap"


class DetectionMaturity(StrEnum):
    PRODUCTION = "production"
    TESTING = "testing"
    DEVELOPMENT = "development"
    CONCEPT = "concept"


# --- Models ---


class DetectionCoverageRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    technique_id: str = ""
    tactic: str = ""
    coverage_level: CoverageLevel = CoverageLevel.NO_COVERAGE
    gap_priority: GapPriority = GapPriority.LOW_GAP
    detection_maturity: DetectionMaturity = DetectionMaturity.CONCEPT
    detection_count: int = 0
    estimated_effort_days: float = 0.0
    risk_weight: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class DetectionCoverageAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    technique_id: str = ""
    coverage_level: CoverageLevel = CoverageLevel.NO_COVERAGE
    gap_priority: GapPriority = GapPriority.LOW_GAP
    coverage_score: float = 0.0
    effort_estimate_days: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class DetectionCoverageReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_risk_weight: float = 0.0
    by_coverage_level: dict[str, int] = Field(default_factory=dict)
    by_gap_priority: dict[str, int] = Field(default_factory=dict)
    by_detection_maturity: dict[str, int] = Field(default_factory=dict)
    critical_gap_techniques: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class RbaDetectionCoverageEngine:
    """Map detection coverage to MITRE matrix, prioritize coverage gaps,
    estimate detection development effort."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[DetectionCoverageRecord] = []
        self._analyses: dict[str, DetectionCoverageAnalysis] = {}
        logger.info("rba_detection_coverage_engine.init", max_records=max_records)

    def add_record(
        self,
        technique_id: str = "",
        tactic: str = "",
        coverage_level: CoverageLevel = CoverageLevel.NO_COVERAGE,
        gap_priority: GapPriority = GapPriority.LOW_GAP,
        detection_maturity: DetectionMaturity = DetectionMaturity.CONCEPT,
        detection_count: int = 0,
        estimated_effort_days: float = 0.0,
        risk_weight: float = 0.0,
        description: str = "",
    ) -> DetectionCoverageRecord:
        record = DetectionCoverageRecord(
            technique_id=technique_id,
            tactic=tactic,
            coverage_level=coverage_level,
            gap_priority=gap_priority,
            detection_maturity=detection_maturity,
            detection_count=detection_count,
            estimated_effort_days=estimated_effort_days,
            risk_weight=risk_weight,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "detection_coverage.record_added",
            record_id=record.id,
            technique_id=technique_id,
        )
        return record

    def process(self, key: str) -> DetectionCoverageAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        coverage_scores = {
            CoverageLevel.FULL_COVERAGE: 100.0,
            CoverageLevel.PARTIAL_COVERAGE: 60.0,
            CoverageLevel.MINIMAL_COVERAGE: 25.0,
            CoverageLevel.NO_COVERAGE: 0.0,
        }
        cov_score = coverage_scores.get(rec.coverage_level, 0.0)
        analysis = DetectionCoverageAnalysis(
            technique_id=rec.technique_id,
            coverage_level=rec.coverage_level,
            gap_priority=rec.gap_priority,
            coverage_score=cov_score,
            effort_estimate_days=rec.estimated_effort_days,
            description=f"Technique {rec.technique_id} coverage={cov_score}%",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> DetectionCoverageReport:
        by_cl: dict[str, int] = {}
        by_gp: dict[str, int] = {}
        by_dm: dict[str, int] = {}
        weights: list[float] = []
        crit_gaps: list[str] = []
        for r in self._records:
            by_cl[r.coverage_level.value] = by_cl.get(r.coverage_level.value, 0) + 1
            by_gp[r.gap_priority.value] = by_gp.get(r.gap_priority.value, 0) + 1
            by_dm[r.detection_maturity.value] = by_dm.get(r.detection_maturity.value, 0) + 1
            weights.append(r.risk_weight)
            if (
                r.gap_priority == GapPriority.CRITICAL_GAP
                and r.technique_id
                and r.technique_id not in crit_gaps
            ):
                crit_gaps.append(r.technique_id)
        avg_w = round(sum(weights) / len(weights), 4) if weights else 0.0
        recs: list[str] = []
        if crit_gaps:
            recs.append(f"{len(crit_gaps)} techniques with critical detection gaps")
        if not recs:
            recs.append("Detection coverage within acceptable thresholds")
        return DetectionCoverageReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_risk_weight=avg_w,
            by_coverage_level=by_cl,
            by_gap_priority=by_gp,
            by_detection_maturity=by_dm,
            critical_gap_techniques=crit_gaps[:10],
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        cl_dist: dict[str, int] = {}
        for r in self._records:
            cl_dist[r.coverage_level.value] = cl_dist.get(r.coverage_level.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "coverage_level_distribution": cl_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("rba_detection_coverage_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def map_coverage_to_matrix(self) -> list[dict[str, Any]]:
        """Map detection coverage to MITRE ATT&CK matrix by tactic and technique."""
        tactic_coverage: dict[str, dict[str, Any]] = {}
        for r in self._records:
            if r.tactic not in tactic_coverage:
                tactic_coverage[r.tactic] = {
                    "tactic": r.tactic,
                    "technique_ids": [],
                    "full_count": 0,
                    "partial_count": 0,
                    "no_coverage_count": 0,
                    "total": 0,
                }
            tc = tactic_coverage[r.tactic]
            tc["total"] += 1
            if r.technique_id not in tc["technique_ids"]:
                tc["technique_ids"].append(r.technique_id)
            if r.coverage_level == CoverageLevel.FULL_COVERAGE:
                tc["full_count"] += 1
            elif r.coverage_level in (
                CoverageLevel.PARTIAL_COVERAGE,
                CoverageLevel.MINIMAL_COVERAGE,
            ):
                tc["partial_count"] += 1
            else:
                tc["no_coverage_count"] += 1
        results: list[dict[str, Any]] = []
        for tactic, data in tactic_coverage.items():
            total = data["total"]
            cov_pct = (
                round((data["full_count"] + data["partial_count"] * 0.5) / total * 100, 2)
                if total
                else 0.0
            )
            results.append(
                {
                    "tactic": tactic,
                    "technique_count": len(data["technique_ids"]),
                    "full_coverage_count": data["full_count"],
                    "partial_coverage_count": data["partial_count"],
                    "no_coverage_count": data["no_coverage_count"],
                    "coverage_pct": cov_pct,
                }
            )
        results.sort(key=lambda x: x["coverage_pct"])
        return results

    def prioritize_coverage_gaps(self) -> list[dict[str, Any]]:
        """Prioritize coverage gaps by risk weight and gap priority."""
        gap_weights = {
            GapPriority.CRITICAL_GAP: 4,
            GapPriority.HIGH_GAP: 3,
            GapPriority.MEDIUM_GAP: 2,
            GapPriority.LOW_GAP: 1,
        }
        tech_latest: dict[str, DetectionCoverageRecord] = {}
        for r in self._records:
            tech_latest[r.technique_id] = r
        results: list[dict[str, Any]] = []
        for tid, rec in tech_latest.items():
            if rec.coverage_level in (
                CoverageLevel.NO_COVERAGE,
                CoverageLevel.MINIMAL_COVERAGE,
            ):
                gw = gap_weights.get(rec.gap_priority, 1)
                priority_score = round(gw * rec.risk_weight, 4)
                results.append(
                    {
                        "technique_id": tid,
                        "tactic": rec.tactic,
                        "coverage_level": rec.coverage_level.value,
                        "gap_priority": rec.gap_priority.value,
                        "risk_weight": rec.risk_weight,
                        "priority_score": priority_score,
                    }
                )
        results.sort(key=lambda x: x["priority_score"], reverse=True)
        return results

    def estimate_detection_development_effort(self) -> list[dict[str, Any]]:
        """Estimate total effort to close detection gaps."""
        tech_recs: dict[str, list[DetectionCoverageRecord]] = {}
        for r in self._records:
            tech_recs.setdefault(r.technique_id, []).append(r)
        results: list[dict[str, Any]] = []
        for tid, recs in tech_recs.items():
            latest = recs[-1]
            maturity_effort_mult = {
                DetectionMaturity.CONCEPT: 3.0,
                DetectionMaturity.DEVELOPMENT: 2.0,
                DetectionMaturity.TESTING: 1.0,
                DetectionMaturity.PRODUCTION: 0.0,
            }
            mult = maturity_effort_mult.get(latest.detection_maturity, 1.0)
            adjusted_effort = round(latest.estimated_effort_days * mult, 2)
            results.append(
                {
                    "technique_id": tid,
                    "detection_maturity": latest.detection_maturity.value,
                    "base_effort_days": latest.estimated_effort_days,
                    "adjusted_effort_days": adjusted_effort,
                    "coverage_level": latest.coverage_level.value,
                    "gap_priority": latest.gap_priority.value,
                }
            )
        results.sort(key=lambda x: x["adjusted_effort_days"], reverse=True)
        return results
