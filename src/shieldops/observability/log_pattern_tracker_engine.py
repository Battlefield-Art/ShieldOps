"""Log Pattern Tracker Engine — track log pattern evolution and frequency."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PatternStatus(StrEnum):
    STABLE = "stable"
    INCREASING = "increasing"
    DECREASING = "decreasing"
    NEW = "new"
    DISAPPEARED = "disappeared"


class PatternCategory(StrEnum):
    NORMAL = "normal"
    ANOMALOUS = "anomalous"
    ERROR = "error"
    SECURITY = "security"
    PERFORMANCE = "performance"


class EvolutionType(StrEnum):
    FREQUENCY_CHANGE = "frequency_change"
    FORMAT_CHANGE = "format_change"
    NEW_PATTERN = "new_pattern"
    PATTERN_SPLIT = "pattern_split"
    PATTERN_MERGE = "pattern_merge"


# --- Models ---


class LogPatternTrackerRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    pattern_id: str = ""
    service_id: str = ""
    pattern_status: PatternStatus = PatternStatus.STABLE
    pattern_category: PatternCategory = PatternCategory.NORMAL
    evolution_type: EvolutionType = EvolutionType.FREQUENCY_CHANGE
    frequency_per_hour: float = 0.0
    previous_frequency: float = 0.0
    change_pct: float = 0.0
    sample_log: str = ""
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class LogPatternTrackerAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    pattern_id: str = ""
    analysis_score: float = 0.0
    pattern_status: PatternStatus = PatternStatus.STABLE
    trend_direction: str = ""
    data_points: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class LogPatternTrackerReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_frequency: float = 0.0
    by_status: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_evolution: dict[str, int] = Field(default_factory=dict)
    high_frequency_patterns: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class LogPatternTrackerEngine:
    """Track log pattern evolution and frequency across services."""

    def __init__(
        self,
        max_records: int = 200000,
        frequency_threshold: float = 100.0,
    ) -> None:
        self._max_records = max_records
        self._frequency_threshold = frequency_threshold
        self._records: list[LogPatternTrackerRecord] = []
        self._analyses: dict[str, LogPatternTrackerAnalysis] = {}
        logger.info(
            "log_pattern_tracker_engine.init",
            max_records=max_records,
            frequency_threshold=frequency_threshold,
        )

    def add_record(
        self,
        pattern_id: str = "",
        service_id: str = "",
        pattern_status: PatternStatus = PatternStatus.STABLE,
        pattern_category: PatternCategory = PatternCategory.NORMAL,
        evolution_type: EvolutionType = EvolutionType.FREQUENCY_CHANGE,
        frequency_per_hour: float = 0.0,
        previous_frequency: float = 0.0,
        change_pct: float = 0.0,
        sample_log: str = "",
        description: str = "",
    ) -> LogPatternTrackerRecord:
        record = LogPatternTrackerRecord(
            pattern_id=pattern_id,
            service_id=service_id,
            pattern_status=pattern_status,
            pattern_category=pattern_category,
            evolution_type=evolution_type,
            frequency_per_hour=frequency_per_hour,
            previous_frequency=previous_frequency,
            change_pct=change_pct,
            sample_log=sample_log,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "log_pattern_tracker_engine.record_added",
            record_id=record.id,
            pattern_id=pattern_id,
        )
        return record

    def process(
        self, key: str,
    ) -> LogPatternTrackerAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        pat_recs = [
            r for r in self._records if r.pattern_id == rec.pattern_id
        ]
        freqs = [r.frequency_per_hour for r in pat_recs]
        if len(freqs) >= 2:
            mid = len(freqs) // 2
            first = sum(freqs[:mid]) / mid
            second = sum(freqs[mid:]) / len(freqs[mid:])
            delta = second - first
            direction = (
                "stable"
                if abs(delta) < 5.0
                else ("increasing" if delta > 0 else "decreasing")
            )
        else:
            direction = "insufficient_data"
        score = round(rec.change_pct, 2)
        analysis = LogPatternTrackerAnalysis(
            pattern_id=rec.pattern_id,
            analysis_score=score,
            pattern_status=rec.pattern_status,
            trend_direction=direction,
            data_points=len(pat_recs),
            description=(
                f"Pattern {rec.pattern_id} trend: {direction}"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> LogPatternTrackerReport:
        by_s: dict[str, int] = {}
        by_c: dict[str, int] = {}
        by_e: dict[str, int] = {}
        freqs: list[float] = []
        for r in self._records:
            by_s[r.pattern_status.value] = (
                by_s.get(r.pattern_status.value, 0) + 1
            )
            by_c[r.pattern_category.value] = (
                by_c.get(r.pattern_category.value, 0) + 1
            )
            by_e[r.evolution_type.value] = (
                by_e.get(r.evolution_type.value, 0) + 1
            )
            freqs.append(r.frequency_per_hour)
        avg_freq = round(sum(freqs) / len(freqs), 2) if freqs else 0.0
        high_freq = list(
            {
                r.pattern_id
                for r in self._records
                if r.frequency_per_hour > self._frequency_threshold
            }
        )[:10]
        recs: list[str] = []
        new_count = by_s.get(PatternStatus.NEW.value, 0)
        if new_count:
            recs.append(f"{new_count} new log patterns detected")
        if high_freq:
            recs.append(
                f"{len(high_freq)} patterns above frequency threshold"
                f" {self._frequency_threshold}/hr"
            )
        anomalous = by_c.get(PatternCategory.ANOMALOUS.value, 0)
        if anomalous:
            recs.append(f"{anomalous} anomalous patterns require review")
        if not recs:
            recs.append("Log patterns stable — no significant evolution")
        return LogPatternTrackerReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_frequency=avg_freq,
            by_status=by_s,
            by_category=by_c,
            by_evolution=by_e,
            high_frequency_patterns=high_freq,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        status_dist: dict[str, int] = {}
        for r in self._records:
            k = r.pattern_status.value
            status_dist[k] = status_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "frequency_threshold": self._frequency_threshold,
            "status_distribution": status_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("log_pattern_tracker_engine.cleared")
        return {"status": "cleared"}

    # -- domain methods ---

    def detect_pattern_evolution(self) -> list[dict[str, Any]]:
        """Detect patterns that have significantly evolved."""
        results: list[dict[str, Any]] = []
        seen: set[str] = set()
        for r in self._records:
            if r.pattern_id not in seen and abs(r.change_pct) > 50.0:
                seen.add(r.pattern_id)
                results.append(
                    {
                        "pattern_id": r.pattern_id,
                        "service_id": r.service_id,
                        "evolution_type": r.evolution_type.value,
                        "change_pct": r.change_pct,
                        "current_frequency": r.frequency_per_hour,
                        "previous_frequency": r.previous_frequency,
                    }
                )
        results.sort(key=lambda x: abs(x["change_pct"]), reverse=True)
        return results

    def rank_patterns_by_frequency(self) -> list[dict[str, Any]]:
        """Rank log patterns by current frequency."""
        pattern_freq: dict[str, float] = {}
        pattern_svc: dict[str, str] = {}
        for r in self._records:
            if (
                r.pattern_id not in pattern_freq
                or r.frequency_per_hour > pattern_freq[r.pattern_id]
            ):
                pattern_freq[r.pattern_id] = r.frequency_per_hour
                pattern_svc[r.pattern_id] = r.service_id
        results: list[dict[str, Any]] = []
        for pid, freq in pattern_freq.items():
            results.append(
                {
                    "pattern_id": pid,
                    "service_id": pattern_svc[pid],
                    "frequency_per_hour": freq,
                }
            )
        results.sort(key=lambda x: x["frequency_per_hour"], reverse=True)
        return results

    def summarize_evolution_by_service(self) -> list[dict[str, Any]]:
        """Summarize pattern evolution counts per service."""
        svc_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            svc_data.setdefault(r.service_id, {"total": 0, "evolved": 0})
            svc_data[r.service_id]["total"] += 1
            if abs(r.change_pct) > 20.0:
                svc_data[r.service_id]["evolved"] += 1
        results: list[dict[str, Any]] = []
        for sid, data in svc_data.items():
            rate = (
                round(data["evolved"] / data["total"] * 100, 2)
                if data["total"]
                else 0.0
            )
            results.append(
                {
                    "service_id": sid,
                    "total_patterns": data["total"],
                    "evolved_patterns": data["evolved"],
                    "evolution_rate_pct": rate,
                }
            )
        results.sort(key=lambda x: x["evolution_rate_pct"], reverse=True)
        return results
