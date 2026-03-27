"""OffensiveSecurityMetrics — Offensive security KPIs."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class AttackSurface(StrEnum):
    EXTERNAL = "external"
    INTERNAL = "internal"
    CLOUD = "cloud"
    API = "api"
    SUPPLY_CHAIN = "supply_chain"
    SOCIAL = "social"


class FindingDensity(StrEnum):
    VERY_HIGH = "very_high"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    MINIMAL = "minimal"


class RemediationSpeed(StrEnum):
    WITHIN_SLA = "within_sla"
    NEAR_SLA = "near_sla"
    EXCEEDED_SLA = "exceeded_sla"
    UNRESOLVED = "unresolved"


# --- Models ---


class OffensiveMetricRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    surface: AttackSurface = AttackSurface.EXTERNAL
    density: FindingDensity = FindingDensity.MODERATE
    speed: RemediationSpeed = RemediationSpeed.WITHIN_SLA
    score: float = 0.0
    findings_count: int = 0
    remediation_days: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class OffensiveMetricAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    surface: AttackSurface = AttackSurface.EXTERNAL
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class OffensiveMetricReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_surface: dict[str, int] = Field(default_factory=dict)
    by_density: dict[str, int] = Field(default_factory=dict)
    by_speed: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class OffensiveSecurityMetrics:
    """Track offensive security KPIs and posture."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[OffensiveMetricRecord] = []
        self._analyses: list[OffensiveMetricAnalysis] = []
        logger.info(
            "offensive_security_metrics.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    def add_record(
        self,
        name: str,
        surface: AttackSurface = (AttackSurface.EXTERNAL),
        density: FindingDensity = (FindingDensity.MODERATE),
        speed: RemediationSpeed = (RemediationSpeed.WITHIN_SLA),
        score: float = 0.0,
        findings_count: int = 0,
        remediation_days: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> OffensiveMetricRecord:
        record = OffensiveMetricRecord(
            name=name,
            surface=surface,
            density=density,
            speed=speed,
            score=score,
            findings_count=findings_count,
            remediation_days=remediation_days,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "offensive_security_metrics.record_added",
            record_id=record.id,
            name=name,
            surface=surface.value,
        )
        return record

    def get_record(self, record_id: str) -> OffensiveMetricRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        surface: AttackSurface | None = None,
        density: FindingDensity | None = None,
        limit: int = 50,
    ) -> list[OffensiveMetricRecord]:
        results = list(self._records)
        if surface is not None:
            results = [r for r in results if r.surface == surface]
        if density is not None:
            results = [r for r in results if r.density == density]
        return results[-limit:]

    # -- domain operations --------------------------------

    def measure_finding_density(
        self,
    ) -> dict[str, Any]:
        """Measure finding density per surface."""
        surface_data: dict[str, list[int]] = {}
        for r in self._records:
            surface_data.setdefault(r.surface.value, []).append(r.findings_count)
        result: dict[str, Any] = {}
        for sfc, counts in surface_data.items():
            result[sfc] = {
                "total_findings": sum(counts),
                "avg_per_test": (round(sum(counts) / len(counts), 1) if counts else 0.0),
                "tests": len(counts),
            }
        return result

    def track_remediation_velocity(
        self,
    ) -> list[dict[str, Any]]:
        """Track how fast findings get remediated."""
        svc_data: dict[str, list[float]] = {}
        for r in self._records:
            if r.remediation_days > 0:
                svc_data.setdefault(r.service, []).append(r.remediation_days)
        results: list[dict[str, Any]] = []
        for svc, days in svc_data.items():
            avg_days = round(sum(days) / len(days), 1)
            results.append(
                {
                    "service": svc,
                    "avg_remediation_days": avg_days,
                    "total_findings": len(days),
                    "within_sla": sum(1 for d in days if d <= 30),
                }
            )
        return sorted(
            results,
            key=lambda x: x["avg_remediation_days"],
            reverse=True,
        )

    def benchmark_security_posture(
        self,
    ) -> dict[str, Any]:
        """Benchmark overall security posture."""
        if not self._records:
            return {"posture_score": 0.0}
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2)
        sla_met = sum(1 for r in self._records if r.speed == RemediationSpeed.WITHIN_SLA)
        return {
            "posture_score": avg,
            "total_assessments": len(self._records),
            "sla_compliance_rate": round(sla_met / len(self._records), 3),
            "high_density_areas": sum(
                1
                for r in self._records
                if r.density
                in (
                    FindingDensity.VERY_HIGH,
                    FindingDensity.HIGH,
                )
            ),
        }

    # -- standard methods ---------------------------------

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
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
        }

    def generate_report(
        self,
    ) -> OffensiveMetricReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.surface.value] = by_e1.get(r.surface.value, 0) + 1
            by_e2[r.density.value] = by_e2.get(r.density.value, 0) + 1
            by_e3[r.speed.value] = by_e3.get(r.speed.value, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_ct = sum(1 for r in self._records if r.score < self._threshold)
        recs: list[str] = []
        if gap_ct > 0:
            recs.append(f"{gap_ct} metric(s) below threshold")
        if not recs:
            recs.append("Offensive security metrics healthy")
        return OffensiveMetricReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_ct,
            avg_score=avg,
            by_surface=by_e1,
            by_density=by_e2,
            by_speed=by_e3,
            top_gaps=[],
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.surface.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "surface_distribution": dist,
            "unique_services": len({r.service for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("offensive_security_metrics.cleared")
        return {"status": "cleared"}
