"""CIS Benchmark Scorer Engine — track CIS benchmark compliance scores."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class BenchmarkType(StrEnum):
    CIS_AWS = "cis_aws"
    CIS_GCP = "cis_gcp"
    CIS_AZURE = "cis_azure"
    CIS_K8S = "cis_k8s"
    CIS_DOCKER = "cis_docker"


class ControlStatus(StrEnum):
    PASS = "pass"  # noqa: S105
    FAIL = "fail"
    WARN = "warn"
    NOT_APPLICABLE = "not_applicable"
    MANUAL = "manual"


class ControlLevel(StrEnum):
    LEVEL_1 = "level_1"
    LEVEL_2 = "level_2"
    CUSTOM = "custom"


# --- Models ---


class CISBenchmarkRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    control_id: str = ""
    benchmark_type: BenchmarkType = BenchmarkType.CIS_AWS
    control_status: ControlStatus = ControlStatus.PASS
    control_level: ControlLevel = ControlLevel.LEVEL_1
    score: float = 0.0
    resources_assessed: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CISBenchmarkAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    benchmark_type: BenchmarkType = BenchmarkType.CIS_AWS
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CISBenchmarkReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_benchmark_type: dict[str, int] = Field(default_factory=dict)
    by_control_status: dict[str, int] = Field(default_factory=dict)
    by_control_level: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class CISBenchmarkScorerEngine:
    """CIS Benchmark Scorer Engine — track CIS benchmark compliance scores."""

    def __init__(
        self,
        max_records: int = 200000,
        compliance_threshold: float = 85.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = compliance_threshold
        self._records: list[CISBenchmarkRecord] = []
        self._analyses: list[CISBenchmarkAnalysis] = []
        logger.info(
            "cis_benchmark_scorer_engine.initialized",
            max_records=max_records,
            compliance_threshold=compliance_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        control_id: str,
        benchmark_type: BenchmarkType = BenchmarkType.CIS_AWS,
        control_status: ControlStatus = ControlStatus.PASS,
        control_level: ControlLevel = ControlLevel.LEVEL_1,
        score: float = 0.0,
        resources_assessed: int = 0,
        service: str = "",
        team: str = "",
    ) -> CISBenchmarkRecord:
        record = CISBenchmarkRecord(
            control_id=control_id,
            benchmark_type=benchmark_type,
            control_status=control_status,
            control_level=control_level,
            score=score,
            resources_assessed=resources_assessed,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "cis_benchmark_scorer_engine.record_added",
            record_id=record.id,
            control_id=control_id,
            benchmark_type=benchmark_type.value,
            control_status=control_status.value,
        )
        return record

    def get_record(self, record_id: str) -> CISBenchmarkRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        benchmark_type: BenchmarkType | None = None,
        control_status: ControlStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[CISBenchmarkRecord]:
        results = list(self._records)
        if benchmark_type is not None:
            results = [r for r in results if r.benchmark_type == benchmark_type]
        if control_status is not None:
            results = [r for r in results if r.control_status == control_status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        benchmark_type: BenchmarkType = BenchmarkType.CIS_AWS,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> CISBenchmarkAnalysis:
        analysis = CISBenchmarkAnalysis(
            name=name,
            benchmark_type=benchmark_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "cis_benchmark_scorer_engine.analysis_added",
            name=name,
            benchmark_type=benchmark_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_benchmark_coverage(self) -> dict[str, Any]:
        bench_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.benchmark_type.value
            bench_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in bench_data.items():
            result[k] = {
                "count": len(scores),
                "avg_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_failing_controls(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.control_status in (ControlStatus.FAIL, ControlStatus.WARN):
                results.append(
                    {
                        "record_id": r.id,
                        "control_id": r.control_id,
                        "benchmark_type": r.benchmark_type.value,
                        "control_status": r.control_status.value,
                        "control_level": r.control_level.value,
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def detect_compliance_trends(self) -> dict[str, Any]:
        if len(self._analyses) < 2:
            return {"trend": "insufficient_data", "delta": 0.0}
        vals = [a.analysis_score for a in self._analyses]
        mid = len(vals) // 2
        first_half = vals[:mid]
        second_half = vals[mid:]
        avg_first = sum(first_half) / len(first_half)
        avg_second = sum(second_half) / len(second_half)
        delta = round(avg_second - avg_first, 2)
        if abs(delta) < 5.0:
            trend = "stable"
        elif delta > 0:
            trend = "improving"
        else:
            trend = "degrading"
        return {
            "trend": trend,
            "delta": delta,
            "avg_first_half": round(avg_first, 2),
            "avg_second_half": round(avg_second, 2),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> CISBenchmarkReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.benchmark_type.value] = by_e1.get(r.benchmark_type.value, 0) + 1
            by_e2[r.control_status.value] = by_e2.get(r.control_status.value, 0) + 1
            by_e3[r.control_level.value] = by_e3.get(r.control_level.value, 0) + 1
        gap_count = sum(
            1 for r in self._records if r.control_status in (ControlStatus.FAIL, ControlStatus.WARN)
        )
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_failing_controls()
        top_gaps = [g["control_id"] for g in gap_list[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} control(s) failing or warning")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("CIS Benchmark Scorer Engine is healthy")
        return CISBenchmarkReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_benchmark_type=by_e1,
            by_control_status=by_e2,
            by_control_level=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("cis_benchmark_scorer_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.benchmark_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "compliance_threshold": self._threshold,
            "benchmark_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
