"""APIFuzzingEngine — Track API fuzz testing results."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class FuzzStrategy(StrEnum):
    RANDOM = "random"
    MUTATION = "mutation"
    GENERATION = "generation"
    DICTIONARY = "dictionary"
    SMART = "smart"


class ResponseAnomaly(StrEnum):
    NONE = "none"
    ERROR_LEAK = "error_leak"
    CRASH = "crash"
    TIMEOUT = "timeout"
    UNEXPECTED_DATA = "unexpected_data"
    STATUS_ANOMALY = "status_anomaly"


class InputType(StrEnum):
    QUERY_PARAM = "query_param"
    PATH_PARAM = "path_param"
    BODY_JSON = "body_json"
    HEADER = "header"
    COOKIE = "cookie"
    FORM_DATA = "form_data"


# --- Models ---


class APIFuzzRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    endpoint: str = ""
    strategy: FuzzStrategy = FuzzStrategy.RANDOM
    anomaly: ResponseAnomaly = ResponseAnomaly.NONE
    input_type: InputType = InputType.QUERY_PARAM
    score: float = 0.0
    status_code: int = 200
    response_time_ms: float = 0.0
    vulnerability: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class APIFuzzAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    endpoint: str = ""
    strategy: FuzzStrategy = FuzzStrategy.RANDOM
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class APIFuzzReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_strategy: dict[str, int] = Field(default_factory=dict)
    by_anomaly: dict[str, int] = Field(default_factory=dict)
    by_input_type: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class APIFuzzingEngine:
    """Track API fuzz testing and detect vulns."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[APIFuzzRecord] = []
        self._analyses: list[APIFuzzAnalysis] = []
        logger.info(
            "api_fuzzing_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    def add_record(
        self,
        endpoint: str,
        strategy: FuzzStrategy = FuzzStrategy.RANDOM,
        anomaly: ResponseAnomaly = (ResponseAnomaly.NONE),
        input_type: InputType = InputType.QUERY_PARAM,
        score: float = 0.0,
        status_code: int = 200,
        response_time_ms: float = 0.0,
        vulnerability: str = "",
        service: str = "",
        team: str = "",
    ) -> APIFuzzRecord:
        record = APIFuzzRecord(
            endpoint=endpoint,
            strategy=strategy,
            anomaly=anomaly,
            input_type=input_type,
            score=score,
            status_code=status_code,
            response_time_ms=response_time_ms,
            vulnerability=vulnerability,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "api_fuzzing_engine.record_added",
            record_id=record.id,
            endpoint=endpoint,
            strategy=strategy.value,
        )
        return record

    def get_record(self, record_id: str) -> APIFuzzRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        strategy: FuzzStrategy | None = None,
        anomaly: ResponseAnomaly | None = None,
        limit: int = 50,
    ) -> list[APIFuzzRecord]:
        results = list(self._records)
        if strategy is not None:
            results = [r for r in results if r.strategy == strategy]
        if anomaly is not None:
            results = [r for r in results if r.anomaly == anomaly]
        return results[-limit:]

    # -- domain operations --------------------------------

    def track_fuzz_result(self, endpoint: str) -> dict[str, Any]:
        """Track fuzz results for an endpoint."""
        matched = [r for r in self._records if r.endpoint == endpoint]
        anomalies = [r for r in matched if r.anomaly != ResponseAnomaly.NONE]
        return {
            "endpoint": endpoint,
            "total_tests": len(matched),
            "anomaly_count": len(anomalies),
            "anomaly_rate": (round(len(anomalies) / len(matched), 3) if matched else 0.0),
        }

    def detect_anomalous_response(
        self,
    ) -> list[dict[str, Any]]:
        """Detect anomalous API responses."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.anomaly != ResponseAnomaly.NONE:
                results.append(
                    {
                        "record_id": r.id,
                        "endpoint": r.endpoint,
                        "anomaly": r.anomaly.value,
                        "input_type": r.input_type.value,
                        "status_code": r.status_code,
                        "response_time_ms": (r.response_time_ms),
                        "vulnerability": r.vulnerability,
                    }
                )
        return sorted(
            results,
            key=lambda x: x["response_time_ms"],
            reverse=True,
        )

    def classify_vulnerability(
        self,
    ) -> dict[str, list[dict[str, Any]]]:
        """Classify discovered vulnerabilities."""
        vuln_map: dict[str, list[dict[str, Any]]] = {}
        for r in self._records:
            if r.vulnerability:
                vuln_map.setdefault(r.vulnerability, []).append(
                    {
                        "endpoint": r.endpoint,
                        "anomaly": r.anomaly.value,
                        "input_type": r.input_type.value,
                        "score": r.score,
                    }
                )
        return vuln_map

    # -- standard methods ---------------------------------

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.endpoint == key or r.service == key]
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

    def generate_report(self) -> APIFuzzReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.strategy.value] = by_e1.get(r.strategy.value, 0) + 1
            by_e2[r.anomaly.value] = by_e2.get(r.anomaly.value, 0) + 1
            by_e3[r.input_type.value] = by_e3.get(r.input_type.value, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_ct = sum(1 for r in self._records if r.score < self._threshold)
        recs: list[str] = []
        if gap_ct > 0:
            recs.append(f"{gap_ct} fuzz result(s) need review")
        if not recs:
            recs.append("API fuzzing engine healthy")
        return APIFuzzReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_ct,
            avg_score=avg,
            by_strategy=by_e1,
            by_anomaly=by_e2,
            by_input_type=by_e3,
            top_gaps=[],
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.strategy.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "strategy_distribution": dist,
            "unique_endpoints": len({r.endpoint for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("api_fuzzing_engine.cleared")
        return {"status": "cleared"}
