"""Hunt Execution Tracker — track hunts, coverage, and blind spots."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class HuntMethod(StrEnum):
    HYPOTHESIS_DRIVEN = "hypothesis_driven"
    INDICATOR_BASED = "indicator_based"
    BEHAVIOR_BASED = "behavior_based"
    AUTOMATED_SWEEP = "automated_sweep"
    RETROSPECTIVE = "retrospective"


class HuntOutcome(StrEnum):
    THREAT_FOUND = "threat_found"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    CLEAN = "clean"
    INCONCLUSIVE = "inconclusive"
    ABORTED = "aborted"


class CoverageGap(StrEnum):
    NO_TELEMETRY = "no_telemetry"
    INSUFFICIENT_LOGS = "insufficient_logs"
    BLIND_SPOT = "blind_spot"
    TOOL_LIMITATION = "tool_limitation"
    SCOPE_EXCLUDED = "scope_excluded"


# --- Models ---


class HuntExecutionRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    hunt_name: str = ""
    method: HuntMethod = HuntMethod.HYPOTHESIS_DRIVEN
    outcome: HuntOutcome = HuntOutcome.CLEAN
    coverage_gap: CoverageGap | None = None
    scope: str = ""
    duration_hours: float = 0.0
    findings_count: int = 0
    analyst_id: str = ""
    created_at: float = Field(default_factory=time.time)


class HuntCoverageAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_assets: int = 0
    covered_assets: int = 0
    coverage_pct: float = 0.0
    gaps: list[str] = Field(default_factory=list)
    analyzed_at: float = Field(default_factory=time.time)


class HuntExecutionReport(BaseModel):
    total_hunts: int = 0
    threats_found: int = 0
    avg_duration_hours: float = 0.0
    by_method: dict[str, int] = Field(default_factory=dict)
    by_outcome: dict[str, int] = Field(default_factory=dict)
    coverage_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class HuntExecutionTracker:
    """Track threat hunt execution, coverage, and blind spots."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[HuntExecutionRecord] = []
        logger.info(
            "hunt_execution_tracker.initialized",
            max_records=max_records,
        )

    def add_record(self, **kwargs: Any) -> HuntExecutionRecord:
        record = HuntExecutionRecord(**kwargs)
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "hunt_execution_tracker.record_added",
            record_id=record.id,
            hunt_name=record.hunt_name,
        )
        return record

    def process(self, key: str) -> dict[str, Any]:
        matches = [r for r in self._records if r.id == key]
        if not matches:
            return {"found": False, "key": key}
        rec = matches[0]
        return {
            "found": True,
            "id": rec.id,
            "hunt_name": rec.hunt_name,
            "outcome": rec.outcome.value,
        }

    # -- domain methods --

    def track_hunt(
        self,
        hunt_name: str,
        method: HuntMethod = HuntMethod.HYPOTHESIS_DRIVEN,
        outcome: HuntOutcome = HuntOutcome.CLEAN,
        scope: str = "",
        duration_hours: float = 0.0,
        findings_count: int = 0,
        analyst_id: str = "",
    ) -> HuntExecutionRecord:
        """Track a completed hunt execution."""
        record = self.add_record(
            hunt_name=hunt_name,
            method=method,
            outcome=outcome,
            scope=scope,
            duration_hours=duration_hours,
            findings_count=findings_count,
            analyst_id=analyst_id,
        )
        logger.info(
            "hunt_execution_tracker.hunt_tracked",
            hunt_name=hunt_name,
            outcome=outcome.value,
        )
        return record

    def measure_coverage(
        self,
        total_assets: int = 100,
    ) -> HuntCoverageAnalysis:
        """Measure hunt coverage across assets."""
        scopes = {r.scope for r in self._records if r.scope}
        covered = min(len(scopes), total_assets)
        coverage_pct = round(covered / total_assets * 100, 2) if total_assets > 0 else 0.0
        gaps: list[str] = []
        for r in self._records:
            if r.coverage_gap is not None:
                gap_val = r.coverage_gap.value
                if gap_val not in gaps:
                    gaps.append(gap_val)
        return HuntCoverageAnalysis(
            total_assets=total_assets,
            covered_assets=covered,
            coverage_pct=coverage_pct,
            gaps=gaps,
        )

    def identify_blind_spots(self) -> list[dict[str, Any]]:
        """Identify areas not covered by recent hunts."""
        gap_counts: dict[str, int] = {}
        for r in self._records:
            if r.coverage_gap is not None:
                gap_val = r.coverage_gap.value
                gap_counts[gap_val] = gap_counts.get(gap_val, 0) + 1
        spots: list[dict[str, Any]] = []
        for gap, count in sorted(gap_counts.items(), key=lambda x: x[1], reverse=True):
            spots.append({"gap_type": gap, "occurrences": count})
        if not spots:
            spots.append({"gap_type": "none", "occurrences": 0})
        return spots

    # -- report / stats --

    def generate_report(self) -> HuntExecutionReport:
        by_method: dict[str, int] = {}
        by_outcome: dict[str, int] = {}
        total_duration = 0.0
        for r in self._records:
            by_method[r.method.value] = by_method.get(r.method.value, 0) + 1
            by_outcome[r.outcome.value] = by_outcome.get(r.outcome.value, 0) + 1
            total_duration += r.duration_hours
        threats_found = by_outcome.get("threat_found", 0)
        avg_dur = round(total_duration / len(self._records), 2) if self._records else 0.0
        blind_spots = self.identify_blind_spots()
        gaps = [s["gap_type"] for s in blind_spots if s["gap_type"] != "none"]
        recs: list[str] = []
        if threats_found > 0:
            recs.append(f"{threats_found} threat(s) discovered")
        if gaps:
            recs.append(f"Coverage gaps: {', '.join(gaps)}")
        if not recs:
            recs.append("Hunt program operating normally")
        return HuntExecutionReport(
            total_hunts=len(self._records),
            threats_found=threats_found,
            avg_duration_hours=avg_dur,
            by_method=by_method,
            by_outcome=by_outcome,
            coverage_gaps=gaps,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
            "threats_found": sum(1 for r in self._records if r.outcome == HuntOutcome.THREAT_FOUND),
            "unique_analysts": len({r.analyst_id for r in self._records if r.analyst_id}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("hunt_execution_tracker.cleared")
        return {"status": "cleared"}
