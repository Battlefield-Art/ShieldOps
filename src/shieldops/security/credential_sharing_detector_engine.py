"""Credential Sharing Detector Engine — detect service account credential sharing."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SharingMethod(StrEnum):
    IP_OVERLAP = "ip_overlap"
    CONCURRENT_USE = "concurrent_use"
    GEO_IMPOSSIBLE = "geo_impossible"
    TOKEN_REUSE = "token_reuse"  # noqa: S105
    CONFIG_COPY = "config_copy"


class SharingRisk(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    FALSE_POSITIVE = "false_positive"


class DetectionSource(StrEnum):
    AUTH_LOG = "auth_log"
    NETWORK_TRAFFIC = "network_traffic"
    CONFIG_SCAN = "config_scan"
    VAULT_AUDIT = "vault_audit"
    MANUAL = "manual"


# --- Models ---


class CredentialSharingDetectorRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    detection_id: str = ""
    sharing_method: SharingMethod = SharingMethod.IP_OVERLAP
    sharing_risk: SharingRisk = SharingRisk.MEDIUM
    detection_source: DetectionSource = DetectionSource.AUTH_LOG
    account_id: str = ""
    shared_with_count: int = 0
    confidence: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CredentialSharingDetectorAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    detection_id: str = ""
    sharing_method: SharingMethod = SharingMethod.IP_OVERLAP
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CredentialSharingDetectorReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_sharing_method: dict[str, int] = Field(default_factory=dict)
    by_sharing_risk: dict[str, int] = Field(default_factory=dict)
    by_detection_source: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class CredentialSharingDetectorEngine:
    """Detect service account credential sharing across environments."""

    def __init__(
        self,
        max_records: int = 200000,
        confidence_threshold: float = 75.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = confidence_threshold
        self._records: list[CredentialSharingDetectorRecord] = []
        self._analyses: list[CredentialSharingDetectorAnalysis] = []
        logger.info(
            "credential_sharing_detector_engine.initialized",
            max_records=max_records,
            confidence_threshold=confidence_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        detection_id: str,
        sharing_method: SharingMethod = SharingMethod.IP_OVERLAP,
        sharing_risk: SharingRisk = SharingRisk.MEDIUM,
        detection_source: DetectionSource = DetectionSource.AUTH_LOG,
        account_id: str = "",
        shared_with_count: int = 0,
        confidence: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> CredentialSharingDetectorRecord:
        record = CredentialSharingDetectorRecord(
            detection_id=detection_id,
            sharing_method=sharing_method,
            sharing_risk=sharing_risk,
            detection_source=detection_source,
            account_id=account_id,
            shared_with_count=shared_with_count,
            confidence=confidence,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "credential_sharing_detector_engine.record_added",
            record_id=record.id,
            detection_id=detection_id,
            sharing_method=sharing_method.value,
            sharing_risk=sharing_risk.value,
        )
        return record

    def get_record(self, record_id: str) -> CredentialSharingDetectorRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        sharing_method: SharingMethod | None = None,
        sharing_risk: SharingRisk | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[CredentialSharingDetectorRecord]:
        results = list(self._records)
        if sharing_method is not None:
            results = [r for r in results if r.sharing_method == sharing_method]
        if sharing_risk is not None:
            results = [r for r in results if r.sharing_risk == sharing_risk]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        detection_id: str,
        sharing_method: SharingMethod = SharingMethod.IP_OVERLAP,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> CredentialSharingDetectorAnalysis:
        analysis = CredentialSharingDetectorAnalysis(
            detection_id=detection_id,
            sharing_method=sharing_method,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "credential_sharing_detector_engine.analysis_added",
            detection_id=detection_id,
            sharing_method=sharing_method.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_sharing_methods(self) -> list[dict[str, Any]]:
        """Analyze credential sharing by detection method."""
        method_data: dict[str, list[float]] = {}
        for r in self._records:
            method_data.setdefault(r.sharing_method.value, []).append(r.confidence)
        results: list[dict[str, Any]] = []
        for method, confidences in method_data.items():
            avg_conf = round(sum(confidences) / len(confidences), 2) if confidences else 0.0
            high_conf = sum(1 for c in confidences if c >= self._threshold)
            results.append(
                {
                    "sharing_method": method,
                    "detection_count": len(confidences),
                    "avg_confidence": avg_conf,
                    "high_confidence_count": high_conf,
                    "false_positive_count": sum(
                        1
                        for r in self._records
                        if r.sharing_method.value == method
                        and r.sharing_risk == SharingRisk.FALSE_POSITIVE
                    ),
                }
            )
        return sorted(results, key=lambda x: x["detection_count"], reverse=True)

    def identify_critical_sharing(self) -> list[dict[str, Any]]:
        """Identify critical credential sharing incidents."""
        critical: list[dict[str, Any]] = []
        for r in self._records:
            if r.sharing_risk in (SharingRisk.CRITICAL, SharingRisk.HIGH):
                critical.append(
                    {
                        "record_id": r.id,
                        "detection_id": r.detection_id,
                        "account_id": r.account_id,
                        "sharing_method": r.sharing_method.value,
                        "sharing_risk": r.sharing_risk.value,
                        "shared_with_count": r.shared_with_count,
                        "confidence": r.confidence,
                        "service": r.service,
                    }
                )
        return sorted(critical, key=lambda x: x["confidence"], reverse=True)

    def detect_sharing_trends(self) -> list[dict[str, Any]]:
        """Detect credential sharing trends by service."""
        svc_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            svc = r.service or "unknown"
            svc_data.setdefault(svc, {})
            risk = r.sharing_risk.value
            svc_data[svc][risk] = svc_data[svc].get(risk, 0) + 1
        results: list[dict[str, Any]] = []
        for svc, risks in svc_data.items():
            total = sum(risks.values())
            critical_high = risks.get("critical", 0) + risks.get("high", 0)
            results.append(
                {
                    "service": svc,
                    "risk_distribution": risks,
                    "total_detections": total,
                    "critical_high_count": critical_high,
                    "critical_high_pct": round(critical_high / total * 100, 2)
                    if total > 0
                    else 0.0,
                }
            )
        return sorted(results, key=lambda x: x["critical_high_count"], reverse=True)

    # -- standard methods ---------------------------------------------------

    def generate_report(self) -> CredentialSharingDetectorReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.sharing_method.value] = by_e1.get(r.sharing_method.value, 0) + 1
            by_e2[r.sharing_risk.value] = by_e2.get(r.sharing_risk.value, 0) + 1
            by_e3[r.detection_source.value] = by_e3.get(r.detection_source.value, 0) + 1
        scores = [r.confidence for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(
            1 for r in self._records if r.sharing_risk in (SharingRisk.CRITICAL, SharingRisk.HIGH)
        )
        critical = self.identify_critical_sharing()
        top_gaps = [o["detection_id"] for o in critical[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} critical/high-risk sharing incident(s) detected")
        if avg_score < self._threshold:
            recs.append(f"Avg confidence {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("Credential Sharing Detector Engine is healthy")
        return CredentialSharingDetectorReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_sharing_method=by_e1,
            by_sharing_risk=by_e2,
            by_detection_source=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("credential_sharing_detector_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.sharing_method.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "confidence_threshold": self._threshold,
            "sharing_method_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
