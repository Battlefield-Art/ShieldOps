"""OWASPFindingTracker — Track OWASP Top 10 findings."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class OWASPCategory(StrEnum):
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    CRYPTO_FAILURES = "crypto_failures"
    INJECTION = "injection"
    INSECURE_DESIGN = "insecure_design"
    SECURITY_MISCONFIG = "security_misconfig"
    VULNERABLE_COMPONENTS = "vulnerable_components"
    AUTH_FAILURES = "auth_failures"
    INTEGRITY_FAILURES = "integrity_failures"
    LOGGING_FAILURES = "logging_failures"
    SSRF = "ssrf"


class FindingStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    REMEDIATED = "remediated"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"


class RemediationPriority(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# --- Models ---


class OWASPFindingRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    category: OWASPCategory = OWASPCategory.BROKEN_ACCESS_CONTROL
    status: FindingStatus = FindingStatus.OPEN
    priority: RemediationPriority = RemediationPriority.MEDIUM
    score: float = 0.0
    url: str = ""
    description: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class OWASPFindingAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    category: OWASPCategory = OWASPCategory.BROKEN_ACCESS_CONTROL
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class OWASPFindingReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_category: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    by_priority: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class OWASPFindingTracker:
    """Track and prioritize OWASP Top 10 findings."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[OWASPFindingRecord] = []
        self._analyses: list[OWASPFindingAnalysis] = []
        logger.info(
            "owasp_finding_tracker.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    def add_record(
        self,
        name: str,
        category: OWASPCategory = (OWASPCategory.BROKEN_ACCESS_CONTROL),
        status: FindingStatus = FindingStatus.OPEN,
        priority: RemediationPriority = (RemediationPriority.MEDIUM),
        score: float = 0.0,
        url: str = "",
        description: str = "",
        service: str = "",
        team: str = "",
    ) -> OWASPFindingRecord:
        record = OWASPFindingRecord(
            name=name,
            category=category,
            status=status,
            priority=priority,
            score=score,
            url=url,
            description=description,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "owasp_finding_tracker.record_added",
            record_id=record.id,
            name=name,
            category=category.value,
        )
        return record

    def get_record(self, record_id: str) -> OWASPFindingRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        category: OWASPCategory | None = None,
        status: FindingStatus | None = None,
        limit: int = 50,
    ) -> list[OWASPFindingRecord]:
        results = list(self._records)
        if category is not None:
            results = [r for r in results if r.category == category]
        if status is not None:
            results = [r for r in results if r.status == status]
        return results[-limit:]

    # -- domain operations --------------------------------

    def track_finding(self, name: str) -> dict[str, Any]:
        """Track a specific finding by name."""
        matched = [r for r in self._records if r.name == name]
        if not matched:
            return {
                "name": name,
                "status": "not_found",
            }
        latest = matched[-1]
        return {
            "name": name,
            "category": latest.category.value,
            "status": latest.status.value,
            "priority": latest.priority.value,
            "score": latest.score,
        }

    def map_to_owasp(self) -> dict[str, Any]:
        """Map all findings to OWASP categories."""
        mapping: dict[str, list[str]] = {}
        for r in self._records:
            cat = r.category.value
            mapping.setdefault(cat, []).append(r.name)
        return {
            "categories": {
                k: {
                    "count": len(v),
                    "findings": v[:10],
                }
                for k, v in mapping.items()
            },
            "total": len(self._records),
        }

    def prioritize_remediation(
        self,
    ) -> list[dict[str, Any]]:
        """Prioritize open findings for remediation."""
        priority_order = {
            RemediationPriority.CRITICAL: 0,
            RemediationPriority.HIGH: 1,
            RemediationPriority.MEDIUM: 2,
            RemediationPriority.LOW: 3,
            RemediationPriority.INFO: 4,
        }
        open_findings = [r for r in self._records if r.status == FindingStatus.OPEN]
        results: list[dict[str, Any]] = []
        for r in open_findings:
            results.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "category": r.category.value,
                    "priority": r.priority.value,
                    "score": r.score,
                    "url": r.url,
                    "order": priority_order.get(r.priority, 99),
                }
            )
        return sorted(results, key=lambda x: x["order"])

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

    def generate_report(self) -> OWASPFindingReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.category.value] = by_e1.get(r.category.value, 0) + 1
            by_e2[r.status.value] = by_e2.get(r.status.value, 0) + 1
            by_e3[r.priority.value] = by_e3.get(r.priority.value, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_ct = sum(1 for r in self._records if r.score < self._threshold)
        recs: list[str] = []
        if gap_ct > 0:
            recs.append(f"{gap_ct} finding(s) below threshold")
        if not recs:
            recs.append("OWASP finding tracker healthy")
        return OWASPFindingReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_ct,
            avg_score=avg,
            by_category=by_e1,
            by_status=by_e2,
            by_priority=by_e3,
            top_gaps=[],
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.category.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "category_distribution": dist,
            "unique_services": len({r.service for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("owasp_finding_tracker.cleared")
        return {"status": "cleared"}
