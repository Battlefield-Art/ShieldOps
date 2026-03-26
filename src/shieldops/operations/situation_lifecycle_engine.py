"""Situation Lifecycle Engine — track situation phases."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SituationPhase(StrEnum):
    NEW = "new"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    RESPONDING = "responding"
    RESOLVED = "resolved"


class ResolutionMethod(StrEnum):
    AUTO_RESOLVED = "auto_resolved"
    ANALYST_RESOLVED = "analyst_resolved"
    ESCALATED = "escalated"
    SUPPRESSED = "suppressed"


class SLATarget(StrEnum):
    P0_15MIN = "p0_15min"
    P1_1HR = "p1_1hr"
    P2_4HR = "p2_4hr"
    P3_24HR = "p3_24hr"


# --- Models ---


class SituationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    situation_id: str = ""
    title: str = ""
    phase: SituationPhase = SituationPhase.NEW
    resolution: ResolutionMethod | None = None
    sla: SLATarget = SLATarget.P2_4HR
    analyst_id: str = ""
    alert_count: int = 0
    ttrs_seconds: float = 0.0
    sla_breached: bool = False
    created_at: float = Field(default_factory=time.time)
    resolved_at: float = 0.0


class SituationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sla_target: str = ""
    total_situations: int = 0
    resolved_count: int = 0
    avg_ttrs: float = 0.0
    sla_breach_rate: float = 0.0
    auto_resolved_rate: float = 0.0
    analyzed_at: float = Field(default_factory=time.time)


class SituationReport(BaseModel):
    total_situations: int = 0
    by_phase: dict[str, int] = Field(default_factory=dict)
    by_resolution: dict[str, int] = Field(default_factory=dict)
    by_sla: dict[str, int] = Field(default_factory=dict)
    avg_ttrs_seconds: float = 0.0
    sla_breach_rate_pct: float = 0.0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


_SLA_LIMITS: dict[SLATarget, float] = {
    SLATarget.P0_15MIN: 900.0,
    SLATarget.P1_1HR: 3600.0,
    SLATarget.P2_4HR: 14400.0,
    SLATarget.P3_24HR: 86400.0,
}


class SituationLifecycleEngine:
    """Track situation lifecycle and SLA compliance."""

    def __init__(
        self,
        max_records: int = 200000,
    ) -> None:
        self._max_records = max_records
        self._records: list[SituationRecord] = []
        logger.info(
            "situation_lifecycle.initialized",
            max_records=max_records,
        )

    # -- record / query --

    def add_record(
        self,
        situation_id: str = "",
        title: str = "",
        phase: SituationPhase = SituationPhase.NEW,
        resolution: ResolutionMethod | None = None,
        sla: SLATarget = SLATarget.P2_4HR,
        analyst_id: str = "",
        alert_count: int = 0,
    ) -> SituationRecord:
        if not situation_id:
            situation_id = str(uuid.uuid4())[:8]
        record = SituationRecord(
            situation_id=situation_id,
            title=title,
            phase=phase,
            resolution=resolution,
            sla=sla,
            analyst_id=analyst_id,
            alert_count=alert_count,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "situation_lifecycle.record_added",
            record_id=record.id,
            situation_id=situation_id,
            phase=phase.value,
        )
        return record

    def process(self, sla_target: str) -> SituationAnalysis:
        items = [r for r in self._records if r.sla.value == sla_target]
        if not items:
            return SituationAnalysis(sla_target=sla_target)
        resolved = [r for r in items if r.phase == SituationPhase.RESOLVED]
        ttrs_vals = [r.ttrs_seconds for r in resolved if r.ttrs_seconds > 0]
        avg_ttrs = round(sum(ttrs_vals) / len(ttrs_vals), 2) if ttrs_vals else 0.0
        breached = sum(1 for r in items if r.sla_breached)
        breach_rate = round(breached / len(items) * 100, 2)
        auto = sum(1 for r in resolved if r.resolution == ResolutionMethod.AUTO_RESOLVED)
        auto_rate = round(auto / len(resolved) * 100, 2) if resolved else 0.0
        return SituationAnalysis(
            sla_target=sla_target,
            total_situations=len(items),
            resolved_count=len(resolved),
            avg_ttrs=avg_ttrs,
            sla_breach_rate=breach_rate,
            auto_resolved_rate=auto_rate,
        )

    def generate_report(self) -> SituationReport:
        by_phase: dict[str, int] = {}
        by_resolution: dict[str, int] = {}
        by_sla: dict[str, int] = {}
        for r in self._records:
            by_phase[r.phase.value] = by_phase.get(r.phase.value, 0) + 1
            if r.resolution:
                key = r.resolution.value
                by_resolution[key] = by_resolution.get(key, 0) + 1
            by_sla[r.sla.value] = by_sla.get(r.sla.value, 0) + 1
        total = len(self._records)
        ttrs_vals = [r.ttrs_seconds for r in self._records if r.ttrs_seconds > 0]
        avg_ttrs = round(sum(ttrs_vals) / len(ttrs_vals), 2) if ttrs_vals else 0.0
        breached = sum(1 for r in self._records if r.sla_breached)
        breach_rate = round(breached / total * 100, 2) if total else 0.0
        recs: list[str] = []
        if breach_rate > 10:
            recs.append(f"SLA breach rate {breach_rate}% — review routing")
        open_ct = sum(1 for r in self._records if r.phase != SituationPhase.RESOLVED)
        if open_ct > 0:
            recs.append(f"{open_ct} situation(s) still open")
        if not recs:
            recs.append("Situation lifecycle health is good")
        return SituationReport(
            total_situations=total,
            by_phase=by_phase,
            by_resolution=by_resolution,
            by_sla=by_sla,
            avg_ttrs_seconds=avg_ttrs,
            sla_breach_rate_pct=breach_rate,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        phase_dist: dict[str, int] = {}
        for r in self._records:
            key = r.phase.value
            phase_dist[key] = phase_dist.get(key, 0) + 1
        return {
            "total_situations": len(self._records),
            "max_records": self._max_records,
            "phase_distribution": phase_dist,
            "sla_breached": sum(1 for r in self._records if r.sla_breached),
            "unique_analysts": len({r.analyst_id for r in self._records if r.analyst_id}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("situation_lifecycle.cleared")
        return {"status": "cleared"}

    # -- domain operations --

    def track_situation(
        self,
        situation_id: str,
        title: str,
        sla: SLATarget = SLATarget.P2_4HR,
        analyst_id: str = "",
        alert_count: int = 1,
    ) -> dict[str, Any]:
        """Track a new situation through lifecycle."""
        record = self.add_record(
            situation_id=situation_id,
            title=title,
            phase=SituationPhase.NEW,
            sla=sla,
            analyst_id=analyst_id,
            alert_count=alert_count,
        )
        return {
            "record_id": record.id,
            "situation_id": situation_id,
            "title": title,
            "phase": SituationPhase.NEW.value,
            "sla": sla.value,
            "sla_limit_seconds": _SLA_LIMITS[sla],
            "tracked": True,
        }

    def measure_ttrs(
        self,
        situation_id: str,
        resolution: ResolutionMethod = (ResolutionMethod.ANALYST_RESOLVED),
    ) -> dict[str, Any]:
        """Measure time-to-resolve for a situation."""
        records = [r for r in self._records if r.situation_id == situation_id]
        if not records:
            return {
                "situation_id": situation_id,
                "found": False,
            }
        record = records[-1]
        now = time.time()
        ttrs = round(now - record.created_at, 2)
        sla_limit = _SLA_LIMITS[record.sla]
        breached = ttrs > sla_limit
        record.phase = SituationPhase.RESOLVED
        record.resolution = resolution
        record.ttrs_seconds = ttrs
        record.resolved_at = now
        record.sla_breached = breached
        logger.info(
            "situation_lifecycle.ttrs_measured",
            situation_id=situation_id,
            ttrs=ttrs,
            breached=breached,
        )
        return {
            "situation_id": situation_id,
            "found": True,
            "ttrs_seconds": ttrs,
            "sla_target": record.sla.value,
            "sla_limit_seconds": sla_limit,
            "sla_breached": breached,
            "resolution": resolution.value,
        }

    def optimize_routing(
        self,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Suggest routing optimizations."""
        analyst_perf: dict[str, list[float]] = {}
        analyst_breaches: dict[str, int] = {}
        for r in self._records:
            if not r.analyst_id:
                continue
            if r.ttrs_seconds > 0:
                analyst_perf.setdefault(r.analyst_id, []).append(r.ttrs_seconds)
            if r.sla_breached:
                analyst_breaches[r.analyst_id] = analyst_breaches.get(r.analyst_id, 0) + 1
        results: list[dict[str, Any]] = []
        for analyst, times in analyst_perf.items():
            avg_ttrs = round(sum(times) / len(times), 2)
            results.append(
                {
                    "analyst_id": analyst,
                    "avg_ttrs_seconds": avg_ttrs,
                    "total_handled": len(times),
                    "sla_breaches": (analyst_breaches.get(analyst, 0)),
                }
            )
        results.sort(key=lambda x: x["avg_ttrs_seconds"])
        logger.info(
            "situation_lifecycle.routing_optimized",
            analysts=len(results),
        )
        return results[:limit]
