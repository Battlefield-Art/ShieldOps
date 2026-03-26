"""Log Pattern Analyzer Engine — analyze log patterns."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class LogPattern(StrEnum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_ACCESS = "data_access"
    SYSTEM_ERROR = "system_error"
    NETWORK_ACTIVITY = "network_activity"


class PatternFrequency(StrEnum):
    RARE = "rare"
    OCCASIONAL = "occasional"
    FREQUENT = "frequent"
    BURST = "burst"
    CONSTANT = "constant"


class PatternSignificance(StrEnum):
    NOISE = "noise"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# --- Models ---


class LogPatternAnalyzerRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_id: str = ""
    service_id: str = ""
    log_pattern: LogPattern = LogPattern.SYSTEM_ERROR
    pattern_frequency: PatternFrequency = PatternFrequency.OCCASIONAL
    pattern_significance: PatternSignificance = PatternSignificance.LOW
    pattern_text: str = ""
    occurrence_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class LogPatternAnalyzerAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_id: str = ""
    analysis_score: float = 0.0
    log_pattern: LogPattern = LogPattern.SYSTEM_ERROR
    pattern_count: int = 0
    data_points: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class LogPatternAnalyzerReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_occurrence_count: float = 0.0
    by_pattern: dict[str, int] = Field(default_factory=dict)
    by_frequency: dict[str, int] = Field(default_factory=dict)
    by_significance: dict[str, int] = Field(default_factory=dict)
    high_significance_sources: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class LogPatternAnalyzerEngine:
    """Analyze log patterns for anomalies and threats."""

    def __init__(
        self,
        max_records: int = 200000,
        significance_threshold: float = 5.0,
    ) -> None:
        self._max_records = max_records
        self._significance_threshold = significance_threshold
        self._records: list[LogPatternAnalyzerRecord] = []
        self._analyses: dict[str, LogPatternAnalyzerAnalysis] = {}
        logger.info(
            "log_pattern_analyzer_engine.init",
            max_records=max_records,
        )

    def add_record(
        self,
        source_id: str = "",
        service_id: str = "",
        log_pattern: LogPattern = LogPattern.SYSTEM_ERROR,
        pattern_frequency: PatternFrequency = (PatternFrequency.OCCASIONAL),
        pattern_significance: PatternSignificance = (PatternSignificance.LOW),
        pattern_text: str = "",
        occurrence_count: int = 0,
        first_seen: float = 0.0,
        last_seen: float = 0.0,
        description: str = "",
    ) -> LogPatternAnalyzerRecord:
        record = LogPatternAnalyzerRecord(
            source_id=source_id,
            service_id=service_id,
            log_pattern=log_pattern,
            pattern_frequency=pattern_frequency,
            pattern_significance=pattern_significance,
            pattern_text=pattern_text,
            occurrence_count=occurrence_count,
            first_seen=first_seen,
            last_seen=last_seen,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "log_pattern_analyzer_engine.record_added",
            record_id=record.id,
            source_id=source_id,
        )
        return record

    def process(
        self,
        key: str,
    ) -> LogPatternAnalyzerAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        src_recs = [r for r in self._records if r.source_id == rec.source_id]
        count = len(src_recs)
        score = round(max(0.0, 100.0 - count * 8), 2)
        analysis = LogPatternAnalyzerAnalysis(
            source_id=rec.source_id,
            analysis_score=score,
            log_pattern=rec.log_pattern,
            pattern_count=count,
            data_points=count,
            description=(f"Pattern score {score} for {rec.source_id} ({count} patterns)"),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> LogPatternAnalyzerReport:
        by_p: dict[str, int] = {}
        by_f: dict[str, int] = {}
        by_s: dict[str, int] = {}
        occ_counts: list[int] = []
        for r in self._records:
            by_p[r.log_pattern.value] = by_p.get(r.log_pattern.value, 0) + 1
            by_f[r.pattern_frequency.value] = by_f.get(r.pattern_frequency.value, 0) + 1
            by_s[r.pattern_significance.value] = by_s.get(r.pattern_significance.value, 0) + 1
            occ_counts.append(r.occurrence_count)
        avg_occ = round(sum(occ_counts) / len(occ_counts), 2) if occ_counts else 0.0
        src_counts: dict[str, int] = {}
        for r in self._records:
            src_counts[r.source_id] = src_counts.get(r.source_id, 0) + 1
        high_sig = [sid for sid, cnt in src_counts.items() if cnt > self._significance_threshold][
            :10
        ]
        recs: list[str] = []
        crit = by_s.get(PatternSignificance.CRITICAL.value, 0)
        if crit:
            recs.append(f"{crit} critical patterns — investigate")
        if high_sig:
            recs.append(f"{len(high_sig)} sources with high pattern density")
        if not recs:
            recs.append("Log patterns within norms")
        return LogPatternAnalyzerReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_occurrence_count=avg_occ,
            by_pattern=by_p,
            by_frequency=by_f,
            by_significance=by_s,
            high_significance_sources=high_sig,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        pat_dist: dict[str, int] = {}
        for r in self._records:
            k = r.log_pattern.value
            pat_dist[k] = pat_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "significance_threshold": (self._significance_threshold),
            "pattern_distribution": pat_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("log_pattern_analyzer_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def analyze_log_patterns(
        self,
    ) -> list[dict[str, Any]]:
        """Analyze log patterns across sources."""
        pat_data: dict[str, dict[str, Any]] = {}
        for r in self._records:
            k = r.log_pattern.value
            pat_data.setdefault(k, {"count": 0, "sources": set()})
            pat_data[k]["count"] += 1
            pat_data[k]["sources"].add(r.source_id)
        results: list[dict[str, Any]] = []
        for pat, data in pat_data.items():
            results.append(
                {
                    "pattern": pat,
                    "occurrence_count": data["count"],
                    "unique_sources": len(data["sources"]),
                }
            )
        results.sort(
            key=lambda x: x["occurrence_count"],
            reverse=True,
        )
        return results

    def detect_frequency_anomalies(
        self,
    ) -> list[dict[str, Any]]:
        """Detect anomalous frequency patterns."""
        src_freq: dict[str, list[int]] = {}
        for r in self._records:
            src_freq.setdefault(r.source_id, []).append(r.occurrence_count)
        results: list[dict[str, Any]] = []
        for src, counts in src_freq.items():
            avg = sum(counts) / len(counts)
            mx = max(counts)
            if mx > avg * 3 and avg > 0:
                results.append(
                    {
                        "source_id": src,
                        "avg_count": round(avg, 2),
                        "max_count": mx,
                        "anomaly_ratio": round(mx / avg, 2),
                    }
                )
        results.sort(
            key=lambda x: x["anomaly_ratio"],
            reverse=True,
        )
        return results

    def correlate_with_threats(
        self,
    ) -> list[dict[str, Any]]:
        """Correlate log patterns with threats."""
        threat_pats = {
            LogPattern.AUTHENTICATION,
            LogPattern.AUTHORIZATION,
            LogPattern.DATA_ACCESS,
        }
        src_threats: dict[str, int] = {}
        src_total: dict[str, int] = {}
        for r in self._records:
            src_total[r.source_id] = src_total.get(r.source_id, 0) + 1
            if r.log_pattern in threat_pats:
                src_threats[r.source_id] = src_threats.get(r.source_id, 0) + 1
        results: list[dict[str, Any]] = []
        for src, cnt in src_threats.items():
            total = src_total.get(src, 1)
            ratio = round(cnt / total * 100, 2)
            results.append(
                {
                    "source_id": src,
                    "threat_patterns": cnt,
                    "total_patterns": total,
                    "threat_ratio_pct": ratio,
                }
            )
        results.sort(
            key=lambda x: x["threat_ratio_pct"],
            reverse=True,
        )
        return results
