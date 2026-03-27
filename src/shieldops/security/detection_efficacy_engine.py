"""DetectionEfficacyEngine -- measure detection quality."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class TestMethod(StrEnum):
    ATOMIC = "atomic"
    SIMULATION = "simulation"
    REPLAY = "replay"
    PURPLE_TEAM = "purple_team"


class DetectionResult(StrEnum):
    DETECTED = "detected"
    MISSED = "missed"
    PARTIAL = "partial"
    DELAYED = "delayed"


class FalseNegativeRate(StrEnum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


# --- Models ---


class DetectionEfficacyRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    test_method: TestMethod = TestMethod.ATOMIC
    result: DetectionResult = DetectionResult.MISSED
    fn_rate: FalseNegativeRate = FalseNegativeRate.LOW
    score: float = 0.0
    rule_id: str = ""
    technique_id: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class DetectionEfficacyAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    test_method: TestMethod = TestMethod.ATOMIC
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class DetectionEfficacyReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_test_method: dict[str, int] = Field(default_factory=dict)
    by_result: dict[str, int] = Field(default_factory=dict)
    by_fn_rate: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class DetectionEfficacyEngine:
    """Measure detection rule efficacy."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[DetectionEfficacyRecord] = []
        self._analyses: list[DetectionEfficacyAnalysis] = []
        logger.info(
            "detection_efficacy_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    def add_record(
        self,
        name: str,
        test_method: TestMethod = TestMethod.ATOMIC,
        result: DetectionResult = DetectionResult.MISSED,
        fn_rate: FalseNegativeRate = FalseNegativeRate.LOW,
        score: float = 0.0,
        rule_id: str = "",
        technique_id: str = "",
        service: str = "",
        team: str = "",
    ) -> DetectionEfficacyRecord:
        record = DetectionEfficacyRecord(
            name=name,
            test_method=test_method,
            result=result,
            fn_rate=fn_rate,
            score=score,
            rule_id=rule_id,
            technique_id=technique_id,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "detection_efficacy_engine.record_added",
            record_id=record.id,
            name=name,
        )
        return record

    def get_record(self, record_id: str) -> DetectionEfficacyRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        test_method: TestMethod | None = None,
        result: DetectionResult | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[DetectionEfficacyRecord]:
        results = list(self._records)
        if test_method is not None:
            results = [r for r in results if r.test_method == test_method]
        if result is not None:
            results = [r for r in results if r.result == result]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        test_method: TestMethod = TestMethod.ATOMIC,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> DetectionEfficacyAnalysis:
        analysis = DetectionEfficacyAnalysis(
            name=name,
            test_method=test_method,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain operations ---

    def measure_efficacy(
        self,
    ) -> list[dict[str, Any]]:
        """Measure efficacy per test method."""
        method_data: dict[str, list[DetectionEfficacyRecord]] = {}
        for r in self._records:
            method_data.setdefault(r.test_method.value, []).append(r)
        results: list[dict[str, Any]] = []
        for method, records in method_data.items():
            detected = sum(1 for r in records if r.result == DetectionResult.DETECTED)
            total = len(records)
            pct = round(detected / total * 100, 1)
            results.append(
                {
                    "method": method,
                    "total_tests": total,
                    "detected": detected,
                    "efficacy_pct": pct,
                }
            )
        return sorted(
            results,
            key=lambda x: x["efficacy_pct"],
        )

    def track_false_negatives(
        self,
    ) -> list[dict[str, Any]]:
        """Track false negative rates by rule."""
        rule_data: dict[str, list[DetectionEfficacyRecord]] = {}
        for r in self._records:
            if r.result == DetectionResult.MISSED:
                rule_data.setdefault(r.rule_id, []).append(r)
        results: list[dict[str, Any]] = []
        for rule_id, records in rule_data.items():
            results.append(
                {
                    "rule_id": rule_id,
                    "miss_count": len(records),
                    "fn_rate": records[-1].fn_rate.value,
                    "techniques": list({r.technique_id for r in records}),
                }
            )
        return sorted(
            results,
            key=lambda x: x["miss_count"],
            reverse=True,
        )

    def benchmark_detection_rate(
        self,
    ) -> dict[str, Any]:
        """Benchmark overall detection rate."""
        if not self._records:
            return {
                "total": 0,
                "detection_rate": 0.0,
            }
        detected = sum(1 for r in self._records if r.result == DetectionResult.DETECTED)
        total = len(self._records)
        return {
            "total": total,
            "detected": detected,
            "missed": total - detected,
            "detection_rate": round(detected / total * 100, 1),
            "target_rate": self._threshold,
        }

    # -- standard methods ---

    def identify_gaps(
        self,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "test_method": r.test_method.value,
                        "score": r.score,
                        "service": r.service,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.rule_id == key]
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
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    def generate_report(
        self,
    ) -> DetectionEfficacyReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            v1 = r.test_method.value
            by_e1[v1] = by_e1.get(v1, 0) + 1
            v2 = r.result.value
            by_e2[v2] = by_e2.get(v2, 0) + 1
            v3 = r.fn_rate.value
            by_e3[v3] = by_e3.get(v3, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if not recs:
            recs.append("Detection Efficacy Engine healthy")
        return DetectionEfficacyReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg,
            by_test_method=by_e1,
            by_result=by_e2,
            by_fn_rate=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("detection_efficacy_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.test_method.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "test_method_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
