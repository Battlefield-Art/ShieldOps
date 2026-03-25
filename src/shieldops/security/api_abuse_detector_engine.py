"""API Abuse Detector Engine — detect and track API abuse patterns."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class AbusePattern(StrEnum):
    CREDENTIAL_STUFFING = "credential_stuffing"
    SCRAPING = "scraping"
    ENUMERATION = "enumeration"
    RATE_ABUSE = "rate_abuse"
    DATA_HARVESTING = "data_harvesting"


class EndpointCategory(StrEnum):
    AUTH = "auth"
    DATA = "data"
    ADMIN = "admin"
    PUBLIC = "public"
    INTERNAL = "internal"


class MitigationAction(StrEnum):
    RATE_LIMIT = "rate_limit"
    BLOCK_IP = "block_ip"
    CHALLENGE = "challenge"
    ALERT = "alert"
    QUARANTINE = "quarantine"


# --- Models ---


class APIAbuseRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    abuse_pattern: AbusePattern = AbusePattern.RATE_ABUSE
    endpoint_category: EndpointCategory = EndpointCategory.PUBLIC
    mitigation_action: MitigationAction = MitigationAction.ALERT
    source_ip: str = ""
    request_count: int = 0
    time_window_min: int = 0
    blocked: bool = False
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class APIAbuseAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    abuse_pattern: AbusePattern = AbusePattern.RATE_ABUSE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class APIAbuseReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_request_count: float = 0.0
    by_abuse_pattern: dict[str, int] = Field(default_factory=dict)
    by_endpoint_category: dict[str, int] = Field(default_factory=dict)
    by_mitigation_action: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class APIAbuseDetectorEngine:
    """Detect and track API abuse patterns."""

    def __init__(
        self,
        max_records: int = 200000,
        abuse_threshold: float = 100.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = abuse_threshold
        self._records: list[APIAbuseRecord] = []
        self._analyses: list[APIAbuseAnalysis] = []
        logger.info(
            "api_abuse_detector_engine.initialized",
            max_records=max_records,
            abuse_threshold=abuse_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        incident_id: str,
        abuse_pattern: AbusePattern = AbusePattern.RATE_ABUSE,
        endpoint_category: EndpointCategory = EndpointCategory.PUBLIC,
        mitigation_action: MitigationAction = MitigationAction.ALERT,
        source_ip: str = "",
        request_count: int = 0,
        time_window_min: int = 0,
        blocked: bool = False,
        service: str = "",
        team: str = "",
    ) -> APIAbuseRecord:
        record = APIAbuseRecord(
            incident_id=incident_id,
            abuse_pattern=abuse_pattern,
            endpoint_category=endpoint_category,
            mitigation_action=mitigation_action,
            source_ip=source_ip,
            request_count=request_count,
            time_window_min=time_window_min,
            blocked=blocked,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "api_abuse_detector_engine.record_added",
            record_id=record.id,
            incident_id=incident_id,
            abuse_pattern=abuse_pattern.value,
            endpoint_category=endpoint_category.value,
        )
        return record

    def get_record(self, record_id: str) -> APIAbuseRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        abuse_pattern: AbusePattern | None = None,
        endpoint_category: EndpointCategory | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[APIAbuseRecord]:
        results = list(self._records)
        if abuse_pattern is not None:
            results = [r for r in results if r.abuse_pattern == abuse_pattern]
        if endpoint_category is not None:
            results = [r for r in results if r.endpoint_category == endpoint_category]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        incident_id: str,
        abuse_pattern: AbusePattern = AbusePattern.RATE_ABUSE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> APIAbuseAnalysis:
        analysis = APIAbuseAnalysis(
            incident_id=incident_id,
            abuse_pattern=abuse_pattern,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "api_abuse_detector_engine.analysis_added",
            incident_id=incident_id,
            abuse_pattern=abuse_pattern.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_abuse_patterns(self) -> dict[str, Any]:
        """Analyze abuse pattern distribution by endpoint category."""
        pattern_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            key = r.abuse_pattern.value
            pattern_data.setdefault(key, {})
            ep = r.endpoint_category.value
            pattern_data[key][ep] = pattern_data[key].get(ep, 0) + 1
        result: dict[str, Any] = {}
        for pattern, endpoints in pattern_data.items():
            total = sum(endpoints.values())
            reqs = [r.request_count for r in self._records if r.abuse_pattern.value == pattern]
            avg_reqs = round(sum(reqs) / len(reqs), 2) if reqs else 0.0
            result[pattern] = {
                "total": total,
                "endpoints": endpoints,
                "avg_request_count": avg_reqs,
                "above_threshold": avg_reqs > self._threshold,
            }
        return result

    def identify_active_attacks(self) -> list[dict[str, Any]]:
        """Identify active unblocked abuse incidents."""
        active: list[dict[str, Any]] = []
        for r in self._records:
            if not r.blocked and r.request_count > self._threshold:
                active.append(
                    {
                        "record_id": r.id,
                        "incident_id": r.incident_id,
                        "abuse_pattern": r.abuse_pattern.value,
                        "endpoint_category": r.endpoint_category.value,
                        "mitigation_action": r.mitigation_action.value,
                        "source_ip": r.source_ip,
                        "request_count": r.request_count,
                        "time_window_min": r.time_window_min,
                        "service": r.service,
                    }
                )
        return sorted(active, key=lambda x: x["request_count"], reverse=True)

    def detect_abuse_trends(self) -> list[dict[str, Any]]:
        """Detect trends in API abuse over time."""
        buckets: dict[str, list[APIAbuseRecord]] = {}
        for r in self._records:
            day = time.strftime("%Y-%m-%d", time.gmtime(r.created_at))
            buckets.setdefault(day, []).append(r)
        trends: list[dict[str, Any]] = []
        for day, records in sorted(buckets.items()):
            blocked_ct = sum(1 for r in records if r.blocked)
            total_reqs = sum(r.request_count for r in records)
            trends.append(
                {
                    "date": day,
                    "total_incidents": len(records),
                    "blocked": blocked_ct,
                    "total_requests": total_reqs,
                }
            )
        return trends

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> APIAbuseReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.abuse_pattern.value] = by_e1.get(r.abuse_pattern.value, 0) + 1
            by_e2[r.endpoint_category.value] = by_e2.get(r.endpoint_category.value, 0) + 1
            by_e3[r.mitigation_action.value] = by_e3.get(r.mitigation_action.value, 0) + 1
        reqs = [r.request_count for r in self._records]
        avg_reqs = round(sum(reqs) / len(reqs), 2) if reqs else 0.0
        gap_count = sum(
            1 for r in self._records if not r.blocked and r.request_count > self._threshold
        )
        gap_list = self.identify_active_attacks()
        top_gaps = [o["incident_id"] for o in gap_list[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} active unblocked abuse incident(s)")
        if not recs:
            recs.append("API Abuse Detector Engine is healthy")
        return APIAbuseReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_request_count=avg_reqs,
            by_abuse_pattern=by_e1,
            by_endpoint_category=by_e2,
            by_mitigation_action=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("api_abuse_detector_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.abuse_pattern.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "abuse_pattern_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
