"""Scanless Vulnerability Matcher — match software to CVEs without scanning."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class MatchMethod(StrEnum):
    CPE_LOOKUP = "cpe_lookup"
    VERSION_RANGE = "version_range"
    BINARY_FINGERPRINT = "binary_fingerprint"
    SBOM_CORRELATION = "sbom_correlation"
    ADVISORY_MATCH = "advisory_match"


class ConfidenceLevel(StrEnum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SPECULATIVE = "speculative"


class PatchStatus(StrEnum):
    PATCHED = "patched"
    UNPATCHED = "unpatched"
    PATCH_AVAILABLE = "patch_available"
    NO_PATCH = "no_patch"
    MITIGATED = "mitigated"


# --- Models ---


class VulnMatchRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    software: str = ""
    version: str = ""
    cve_id: str = ""
    match_method: MatchMethod = MatchMethod.CPE_LOOKUP
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    patch_status: PatchStatus = PatchStatus.UNPATCHED
    epss_score: float = 0.0
    cvss_score: float = 0.0
    sla_deadline: float = 0.0
    created_at: float = Field(default_factory=time.time)


class VulnMatchAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    match_id: str = ""
    epss_percentile: float = 0.0
    exploitability: str = ""
    recommended_priority: str = ""
    analyzed_at: float = Field(default_factory=time.time)


class VulnMatchReport(BaseModel):
    total_matches: int = 0
    unpatched_count: int = 0
    high_confidence_count: int = 0
    by_method: dict[str, int] = Field(default_factory=dict)
    by_patch_status: dict[str, int] = Field(default_factory=dict)
    avg_epss_score: float = 0.0
    sla_breaches: int = 0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ScanlessVulnMatcher:
    """Match software to CVEs without active scanning."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[VulnMatchRecord] = []
        logger.info(
            "scanless_vuln_matcher.initialized",
            max_records=max_records,
        )

    def add_record(self, **kwargs: Any) -> VulnMatchRecord:
        record = VulnMatchRecord(**kwargs)
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "scanless_vuln_matcher.record_added",
            record_id=record.id,
            cve_id=record.cve_id,
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
            "cve_id": rec.cve_id,
            "confidence": rec.confidence.value,
        }

    # -- domain methods --

    def match_software_to_cve(
        self,
        software: str,
        version: str,
        cve_id: str,
        method: MatchMethod = MatchMethod.CPE_LOOKUP,
        cvss_score: float = 0.0,
        epss_score: float = 0.0,
    ) -> VulnMatchRecord:
        """Match a software/version to a CVE."""
        confidence = ConfidenceLevel.MEDIUM
        if method == MatchMethod.CPE_LOOKUP:
            confidence = ConfidenceLevel.HIGH
        elif method == MatchMethod.BINARY_FINGERPRINT:
            confidence = ConfidenceLevel.CONFIRMED
        record = self.add_record(
            software=software,
            version=version,
            cve_id=cve_id,
            match_method=method,
            confidence=confidence,
            cvss_score=cvss_score,
            epss_score=epss_score,
        )
        logger.info(
            "scanless_vuln_matcher.matched",
            software=software,
            cve_id=cve_id,
            confidence=confidence.value,
        )
        return record

    def calculate_epss_priority(self, match_id: str) -> dict[str, Any]:
        """Calculate priority based on EPSS score."""
        record = None
        for r in self._records:
            if r.id == match_id:
                record = r
                break
        if record is None:
            return {"found": False, "match_id": match_id}
        if record.epss_score >= 0.7:
            priority = "critical"
        elif record.epss_score >= 0.4:
            priority = "high"
        elif record.epss_score >= 0.1:
            priority = "medium"
        else:
            priority = "low"
        return {
            "found": True,
            "match_id": match_id,
            "cve_id": record.cve_id,
            "epss_score": record.epss_score,
            "cvss_score": record.cvss_score,
            "priority": priority,
        }

    def track_remediation_sla(self) -> list[dict[str, Any]]:
        """Track SLA compliance for vulnerability remediation."""
        now = time.time()
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.patch_status == PatchStatus.UNPATCHED and r.sla_deadline > 0:
                breached = now > r.sla_deadline
                results.append(
                    {
                        "match_id": r.id,
                        "cve_id": r.cve_id,
                        "software": r.software,
                        "sla_breached": breached,
                        "days_remaining": round((r.sla_deadline - now) / 86400, 1),
                    }
                )
        results.sort(key=lambda x: x["days_remaining"])
        return results

    # -- report / stats --

    def generate_report(self) -> VulnMatchReport:
        by_method: dict[str, int] = {}
        by_patch: dict[str, int] = {}
        total_epss = 0.0
        now = time.time()
        sla_breaches = 0
        for r in self._records:
            by_method[r.match_method.value] = by_method.get(r.match_method.value, 0) + 1
            by_patch[r.patch_status.value] = by_patch.get(r.patch_status.value, 0) + 1
            total_epss += r.epss_score
            if (
                r.patch_status == PatchStatus.UNPATCHED
                and r.sla_deadline > 0
                and now > r.sla_deadline
            ):
                sla_breaches += 1
        unpatched = by_patch.get("unpatched", 0)
        high_conf = sum(
            1
            for r in self._records
            if r.confidence
            in (
                ConfidenceLevel.CONFIRMED,
                ConfidenceLevel.HIGH,
            )
        )
        avg_epss = round(total_epss / len(self._records), 4) if self._records else 0.0
        recs: list[str] = []
        if unpatched > 0:
            recs.append(f"{unpatched} unpatched vulnerability(ies)")
        if sla_breaches > 0:
            recs.append(f"{sla_breaches} SLA breach(es)")
        if not recs:
            recs.append("Vulnerability posture healthy")
        return VulnMatchReport(
            total_matches=len(self._records),
            unpatched_count=unpatched,
            high_confidence_count=high_conf,
            by_method=by_method,
            by_patch_status=by_patch,
            avg_epss_score=avg_epss,
            sla_breaches=sla_breaches,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
            "unpatched": sum(1 for r in self._records if r.patch_status == PatchStatus.UNPATCHED),
            "unique_cves": len({r.cve_id for r in self._records if r.cve_id}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("scanless_vuln_matcher.cleared")
        return {"status": "cleared"}
