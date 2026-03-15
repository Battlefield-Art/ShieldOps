"""IOCLifecycleEngine — track Indicator of Compromise lifecycle from discovery through
validation, deployment to expiry."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class IOCPhase(StrEnum):
    DISCOVERED = "discovered"
    VALIDATED = "validated"
    DEPLOYED = "deployed"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class IOCType(StrEnum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    FILE_HASH = "file_hash"
    URL = "url"
    EMAIL_ADDRESS = "email_address"
    CVE_ID = "cve_id"


class IOCAction(StrEnum):
    BLOCK = "block"
    MONITOR = "monitor"
    ALERT = "alert"
    INVESTIGATE = "investigate"
    IGNORE = "ignore"


# --- Models ---


class IOCLifecycleRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ioc_value: str = ""
    ioc_phase: IOCPhase = IOCPhase.DISCOVERED
    ioc_type: IOCType = IOCType.IP_ADDRESS
    ioc_action: IOCAction = IOCAction.MONITOR
    confidence: float = 0.0
    ttl_seconds: float = 86400.0
    source: str = ""
    detections: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class IOCLifecycleAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ioc_value: str = ""
    ioc_phase: IOCPhase = IOCPhase.DISCOVERED
    ioc_type: IOCType = IOCType.IP_ADDRESS
    recommended_action: str = ""
    risk_assessment: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class IOCLifecycleReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    stale_count: int = 0
    avg_confidence: float = 0.0
    by_ioc_phase: dict[str, int] = Field(default_factory=dict)
    by_ioc_type: dict[str, int] = Field(default_factory=dict)
    by_ioc_action: dict[str, int] = Field(default_factory=dict)
    top_stale: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class IOCLifecycleEngine:
    """Track IOC lifecycle from discovery through validation, deployment to expiry."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[IOCLifecycleRecord] = []
        self._analyses: dict[str, IOCLifecycleAnalysis] = {}
        logger.info("ioc_lifecycle_engine.init", max_records=max_records)

    def add_record(
        self,
        ioc_value: str = "",
        ioc_phase: IOCPhase = IOCPhase.DISCOVERED,
        ioc_type: IOCType = IOCType.IP_ADDRESS,
        ioc_action: IOCAction = IOCAction.MONITOR,
        confidence: float = 0.0,
        ttl_seconds: float = 86400.0,
        source: str = "",
        detections: int = 0,
        description: str = "",
    ) -> IOCLifecycleRecord:
        record = IOCLifecycleRecord(
            ioc_value=ioc_value,
            ioc_phase=ioc_phase,
            ioc_type=ioc_type,
            ioc_action=ioc_action,
            confidence=confidence,
            ttl_seconds=ttl_seconds,
            source=source,
            detections=detections,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "ioc_lifecycle.record_added",
            record_id=record.id,
            ioc_value=ioc_value,
            ioc_phase=ioc_phase.value,
        )
        return record

    def process(self, key: str) -> IOCLifecycleAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        risk = round(rec.confidence * 100, 2)
        if rec.confidence >= 0.8:
            action = "Deploy IOC for active blocking"
        elif rec.confidence >= 0.5:
            action = "Validate IOC with additional sources"
        else:
            action = "Monitor and gather more context"
        analysis = IOCLifecycleAnalysis(
            ioc_value=rec.ioc_value,
            ioc_phase=rec.ioc_phase,
            ioc_type=rec.ioc_type,
            recommended_action=action,
            risk_assessment=risk,
            description=f"IOC {rec.ioc_value} confidence={rec.confidence}",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> IOCLifecycleReport:
        by_phase: dict[str, int] = {}
        by_type: dict[str, int] = {}
        by_action: dict[str, int] = {}
        for r in self._records:
            by_phase[r.ioc_phase.value] = by_phase.get(r.ioc_phase.value, 0) + 1
            by_type[r.ioc_type.value] = by_type.get(r.ioc_type.value, 0) + 1
            by_action[r.ioc_action.value] = by_action.get(r.ioc_action.value, 0) + 1
        now = time.time()
        stale_count = sum(
            1
            for r in self._records
            if (now - r.created_at) > r.ttl_seconds
            and r.ioc_phase not in (IOCPhase.EXPIRED, IOCPhase.REVOKED)
        )
        confidences = [r.confidence for r in self._records]
        avg_confidence = round(sum(confidences) / len(confidences), 2) if confidences else 0.0
        stale_list = self.identify_stale_iocs()
        top_stale = [s["ioc_value"] for s in stale_list[:5]]
        recs: list[str] = []
        if stale_count > 0:
            recs.append(f"{stale_count} IOC(s) past TTL — review or revoke")
        if avg_confidence < 0.5 and self._records:
            recs.append(f"Average confidence {avg_confidence} is low — improve source quality")
        if not recs:
            recs.append("IOC lifecycle engine is healthy")
        return IOCLifecycleReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            stale_count=stale_count,
            avg_confidence=avg_confidence,
            by_ioc_phase=by_phase,
            by_ioc_type=by_type,
            by_ioc_action=by_action,
            top_stale=top_stale,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        phase_dist: dict[str, int] = {}
        for r in self._records:
            phase_dist[r.ioc_phase.value] = phase_dist.get(r.ioc_phase.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "ioc_phase_distribution": phase_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("ioc_lifecycle_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def identify_stale_iocs(self) -> list[dict[str, Any]]:
        """Find IOCs past their TTL that need refresh or revocation."""
        now = time.time()
        results: list[dict[str, Any]] = []
        for r in self._records:
            age = now - r.created_at
            if age > r.ttl_seconds and r.ioc_phase not in (
                IOCPhase.EXPIRED,
                IOCPhase.REVOKED,
            ):
                results.append(
                    {
                        "record_id": r.id,
                        "ioc_value": r.ioc_value,
                        "ioc_type": r.ioc_type.value,
                        "ioc_phase": r.ioc_phase.value,
                        "age_seconds": round(age, 2),
                        "ttl_seconds": r.ttl_seconds,
                        "overdue_by": round(age - r.ttl_seconds, 2),
                    }
                )
        results.sort(key=lambda x: x["overdue_by"], reverse=True)
        return results

    def compute_ioc_effectiveness(self) -> dict[str, Any]:
        """Compute how many IOCs resulted in true detections."""
        if not self._records:
            return {
                "total_iocs": 0,
                "iocs_with_detections": 0,
                "effectiveness_rate": 0.0,
                "avg_detections_per_ioc": 0.0,
                "effectiveness_grade": "no_data",
            }
        total = len(self._records)
        with_detections = sum(1 for r in self._records if r.detections > 0)
        total_detections = sum(r.detections for r in self._records)
        eff_rate = round(with_detections / total * 100, 2)
        avg_det = round(total_detections / total, 2)
        if eff_rate >= 50:
            grade = "excellent"
        elif eff_rate >= 25:
            grade = "good"
        elif eff_rate >= 10:
            grade = "fair"
        else:
            grade = "poor"
        return {
            "total_iocs": total,
            "iocs_with_detections": with_detections,
            "effectiveness_rate": eff_rate,
            "avg_detections_per_ioc": avg_det,
            "effectiveness_grade": grade,
        }

    def recommend_ioc_actions(self) -> list[dict[str, Any]]:
        """Suggest actions for newly discovered IOCs based on confidence and type."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.ioc_phase != IOCPhase.DISCOVERED:
                continue
            if r.confidence >= 0.85:
                action = IOCAction.BLOCK
                reason = "High confidence — deploy for blocking"
            elif r.confidence >= 0.6:
                action = IOCAction.ALERT
                reason = "Moderate confidence — alert on matches"
            elif r.confidence >= 0.3:
                action = IOCAction.INVESTIGATE
                reason = "Low confidence — needs further investigation"
            else:
                action = IOCAction.IGNORE
                reason = "Very low confidence — likely noise"
            results.append(
                {
                    "record_id": r.id,
                    "ioc_value": r.ioc_value,
                    "ioc_type": r.ioc_type.value,
                    "confidence": r.confidence,
                    "recommended_action": action.value,
                    "reason": reason,
                }
            )
        results.sort(key=lambda x: x["confidence"], reverse=True)
        return results
