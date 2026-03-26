"""Situation Resolution Analytics — measure resolution quality."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ResolutionMetric(StrEnum):
    TTRS = "ttrs"
    ANALYST_ACTIONS = "analyst_actions"
    AUTOMATION_RATE = "automation_rate"
    FP_RATE = "fp_rate"


class AnalystProductivity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AutomationRate(StrEnum):
    FULL = "full"
    PARTIAL = "partial"
    MANUAL = "manual"


# --- Models ---


class ResolutionRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    situation_id: str = ""
    analyst_id: str = ""
    metric: ResolutionMetric = ResolutionMetric.TTRS
    productivity: AnalystProductivity = AnalystProductivity.MEDIUM
    automation: AutomationRate = AutomationRate.MANUAL
    ttrs_seconds: float = 0.0
    action_count: int = 0
    false_positive: bool = False
    created_at: float = Field(default_factory=time.time)


class ResolutionAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    analyst_id: str = ""
    total_resolutions: int = 0
    avg_ttrs: float = 0.0
    avg_actions: float = 0.0
    productivity_class: str = ""
    automation_rate_pct: float = 0.0
    analyzed_at: float = Field(default_factory=time.time)


class ResolutionReport(BaseModel):
    total_resolutions: int = 0
    by_metric: dict[str, int] = Field(default_factory=dict)
    by_productivity: dict[str, int] = Field(default_factory=dict)
    by_automation: dict[str, int] = Field(default_factory=dict)
    avg_ttrs_seconds: float = 0.0
    fp_rate_pct: float = 0.0
    automation_rate_pct: float = 0.0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class SituationResolutionAnalyticsEngine:
    """Measure situation resolution quality."""

    def __init__(
        self,
        max_records: int = 200000,
    ) -> None:
        self._max_records = max_records
        self._records: list[ResolutionRecord] = []
        logger.info(
            "situation_resolution_analytics.initialized",
            max_records=max_records,
        )

    def _classify_productivity(
        self,
        ttrs: float,
        actions: int,
    ) -> AnalystProductivity:
        if ttrs < 900 and actions <= 5:
            return AnalystProductivity.HIGH
        if ttrs < 3600 and actions <= 15:
            return AnalystProductivity.MEDIUM
        return AnalystProductivity.LOW

    # -- record / query --

    def add_record(
        self,
        situation_id: str = "",
        analyst_id: str = "",
        ttrs_seconds: float = 0.0,
        action_count: int = 0,
        automation: AutomationRate = (AutomationRate.MANUAL),
        false_positive: bool = False,
    ) -> ResolutionRecord:
        productivity = self._classify_productivity(ttrs_seconds, action_count)
        record = ResolutionRecord(
            situation_id=situation_id,
            analyst_id=analyst_id,
            metric=ResolutionMetric.TTRS,
            productivity=productivity,
            automation=automation,
            ttrs_seconds=ttrs_seconds,
            action_count=action_count,
            false_positive=false_positive,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "situation_resolution_analytics.record_added",
            record_id=record.id,
            situation_id=situation_id,
            productivity=productivity.value,
        )
        return record

    def process(self, analyst_id: str) -> ResolutionAnalysis:
        items = [r for r in self._records if r.analyst_id == analyst_id]
        if not items:
            return ResolutionAnalysis(analyst_id=analyst_id)
        ttrs_vals = [r.ttrs_seconds for r in items if r.ttrs_seconds > 0]
        avg_ttrs = round(sum(ttrs_vals) / len(ttrs_vals), 2) if ttrs_vals else 0.0
        avg_actions = round(
            sum(r.action_count for r in items) / len(items),
            2,
        )
        prod_counts: dict[str, int] = {}
        for r in items:
            key = r.productivity.value
            prod_counts[key] = prod_counts.get(key, 0) + 1
        dominant = (
            max(
                prod_counts,
                key=prod_counts.get,  # type: ignore[arg-type]
            )
            if prod_counts
            else ""
        )
        auto_ct = sum(1 for r in items if r.automation != AutomationRate.MANUAL)
        auto_rate = round(auto_ct / len(items) * 100, 2)
        return ResolutionAnalysis(
            analyst_id=analyst_id,
            total_resolutions=len(items),
            avg_ttrs=avg_ttrs,
            avg_actions=avg_actions,
            productivity_class=dominant,
            automation_rate_pct=auto_rate,
        )

    def generate_report(
        self,
    ) -> ResolutionReport:
        by_metric: dict[str, int] = {}
        by_prod: dict[str, int] = {}
        by_auto: dict[str, int] = {}
        for r in self._records:
            by_metric[r.metric.value] = by_metric.get(r.metric.value, 0) + 1
            by_prod[r.productivity.value] = by_prod.get(r.productivity.value, 0) + 1
            by_auto[r.automation.value] = by_auto.get(r.automation.value, 0) + 1
        total = len(self._records)
        ttrs_vals = [r.ttrs_seconds for r in self._records if r.ttrs_seconds > 0]
        avg_ttrs = round(sum(ttrs_vals) / len(ttrs_vals), 2) if ttrs_vals else 0.0
        fp_ct = sum(1 for r in self._records if r.false_positive)
        fp_rate = round(fp_ct / total * 100, 2) if total else 0.0
        auto_ct = sum(1 for r in self._records if r.automation != AutomationRate.MANUAL)
        auto_rate = round(auto_ct / total * 100, 2) if total else 0.0
        recs: list[str] = []
        if fp_rate > 20:
            recs.append(f"FP rate {fp_rate}% — tune detection rules")
        low_ct = by_prod.get(AnalystProductivity.LOW.value, 0)
        if low_ct > 0:
            recs.append(f"{low_ct} low-productivity resolution(s) — review workflow")
        if auto_rate < 30 and total > 5:
            recs.append("Low automation — add playbooks for common situations")
        if not recs:
            recs.append("Resolution quality is healthy")
        return ResolutionReport(
            total_resolutions=total,
            by_metric=by_metric,
            by_productivity=by_prod,
            by_automation=by_auto,
            avg_ttrs_seconds=avg_ttrs,
            fp_rate_pct=fp_rate,
            automation_rate_pct=auto_rate,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        prod_dist: dict[str, int] = {}
        for r in self._records:
            key = r.productivity.value
            prod_dist[key] = prod_dist.get(key, 0) + 1
        return {
            "total_resolutions": len(self._records),
            "max_records": self._max_records,
            "productivity_distribution": prod_dist,
            "unique_analysts": len({r.analyst_id for r in self._records if r.analyst_id}),
            "false_positives": sum(1 for r in self._records if r.false_positive),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("situation_resolution_analytics.cleared")
        return {"status": "cleared"}

    # -- domain operations --

    def measure_resolution_speed(
        self,
        window: int = 50,
    ) -> dict[str, Any]:
        """Measure resolution speed trends."""
        recent = self._records[-window:]
        if len(recent) < 2:
            return {
                "sufficient_data": False,
                "count": len(recent),
            }
        ttrs_vals = [r.ttrs_seconds for r in recent if r.ttrs_seconds > 0]
        if not ttrs_vals:
            return {
                "sufficient_data": False,
                "count": 0,
            }
        avg = round(sum(ttrs_vals) / len(ttrs_vals), 2)
        half = len(ttrs_vals) // 2
        first_avg = sum(ttrs_vals[:half]) / max(half, 1)
        second_avg = sum(ttrs_vals[half:]) / max(len(ttrs_vals) - half, 1)
        trend = round(second_avg - first_avg, 2)
        return {
            "sufficient_data": True,
            "avg_ttrs_seconds": avg,
            "trend_seconds": trend,
            "improving": trend < 0,
            "sample_count": len(ttrs_vals),
        }

    def track_analyst_efficiency(
        self,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Track efficiency per analyst."""
        analyst_data: dict[str, list[ResolutionRecord]] = {}
        for r in self._records:
            if r.analyst_id:
                analyst_data.setdefault(r.analyst_id, []).append(r)
        results: list[dict[str, Any]] = []
        for analyst, recs in analyst_data.items():
            ttrs_vals = [r.ttrs_seconds for r in recs if r.ttrs_seconds > 0]
            avg_ttrs = (
                round(
                    sum(ttrs_vals) / len(ttrs_vals),
                    2,
                )
                if ttrs_vals
                else 0.0
            )
            avg_actions = round(
                sum(r.action_count for r in recs) / len(recs),
                2,
            )
            fp_ct = sum(1 for r in recs if r.false_positive)
            results.append(
                {
                    "analyst_id": analyst,
                    "total_resolutions": len(recs),
                    "avg_ttrs_seconds": avg_ttrs,
                    "avg_actions": avg_actions,
                    "fp_count": fp_ct,
                    "productivity": (
                        self._classify_productivity(
                            avg_ttrs,
                            int(avg_actions),
                        ).value
                    ),
                }
            )
        results.sort(key=lambda x: x["avg_ttrs_seconds"])
        return results[:limit]

    def calculate_automation_rate(
        self,
        window: int = 50,
    ) -> dict[str, Any]:
        """Calculate automation rate trends."""
        recent = self._records[-window:]
        if not recent:
            return {
                "total": 0,
                "automation_rate_pct": 0.0,
            }
        full = sum(1 for r in recent if r.automation == AutomationRate.FULL)
        partial = sum(1 for r in recent if r.automation == AutomationRate.PARTIAL)
        manual = sum(1 for r in recent if r.automation == AutomationRate.MANUAL)
        total = len(recent)
        auto_rate = round((full + partial) / total * 100, 2)
        full_rate = round(full / total * 100, 2)
        return {
            "total": total,
            "full_automation": full,
            "partial_automation": partial,
            "manual": manual,
            "automation_rate_pct": auto_rate,
            "full_automation_rate_pct": full_rate,
        }
