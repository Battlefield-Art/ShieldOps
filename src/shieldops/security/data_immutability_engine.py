"""Data Immutability Engine — enforce and audit data immutability protections."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class LockType(StrEnum):
    WORM = "worm"
    OBJECT_LOCK = "object_lock"
    LEGAL_HOLD = "legal_hold"
    SNAPSHOT_LOCK = "snapshot_lock"
    NONE = "none"


class ProtectionPolicy(StrEnum):
    RETENTION_30D = "retention_30d"
    RETENTION_90D = "retention_90d"
    RETENTION_1Y = "retention_1y"
    RETENTION_7Y = "retention_7y"
    INDEFINITE = "indefinite"


class ComplianceRequirement(StrEnum):
    SOC2 = "soc2"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    SEC_17A4 = "sec_17a4"


# --- Models ---


class ImmutabilityRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    resource_name: str = ""
    lock_type: LockType = LockType.NONE
    protection_policy: ProtectionPolicy = ProtectionPolicy.RETENTION_90D
    compliance_requirement: ComplianceRequirement = ComplianceRequirement.SOC2
    protection_score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ImmutabilityAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    resource_name: str = ""
    lock_type: LockType = LockType.NONE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ImmutabilityReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_protection_score: float = 0.0
    by_lock_type: dict[str, int] = Field(default_factory=dict)
    by_policy: dict[str, int] = Field(default_factory=dict)
    by_compliance: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class DataImmutabilityEngine:
    """Enforce and audit data immutability protections."""

    def __init__(
        self,
        max_records: int = 200000,
        protection_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._protection_threshold = protection_threshold
        self._records: list[ImmutabilityRecord] = []
        self._analyses: list[ImmutabilityAnalysis] = []
        logger.info(
            "data_immutability.initialized",
            max_records=max_records,
            protection_threshold=protection_threshold,
        )

    # -- record / get / list ----------------------------

    def add_record(
        self,
        resource_name: str,
        lock_type: LockType = LockType.NONE,
        protection_policy: ProtectionPolicy = (ProtectionPolicy.RETENTION_90D),
        compliance_requirement: ComplianceRequirement = (ComplianceRequirement.SOC2),
        protection_score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> ImmutabilityRecord:
        record = ImmutabilityRecord(
            resource_name=resource_name,
            lock_type=lock_type,
            protection_policy=protection_policy,
            compliance_requirement=compliance_requirement,
            protection_score=protection_score,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "data_immutability.record_added",
            record_id=record.id,
            resource_name=resource_name,
            lock_type=lock_type.value,
        )
        return record

    def get_record(self, record_id: str) -> ImmutabilityRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        lock_type: LockType | None = None,
        compliance_requirement: (ComplianceRequirement | None) = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ImmutabilityRecord]:
        results = list(self._records)
        if lock_type is not None:
            results = [r for r in results if r.lock_type == lock_type]
        if compliance_requirement is not None:
            results = [r for r in results if r.compliance_requirement == compliance_requirement]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        resource_name: str,
        lock_type: LockType = LockType.NONE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> ImmutabilityAnalysis:
        analysis = ImmutabilityAnalysis(
            resource_name=resource_name,
            lock_type=lock_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "data_immutability.analysis_added",
            resource_name=resource_name,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations ------------------------------

    def enforce_immutability(self) -> dict[str, Any]:
        """Group by lock_type; return count and avg protection_score."""
        lock_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.lock_type.value
            lock_data.setdefault(key, []).append(r.protection_score)
        result: dict[str, Any] = {}
        for lock, scores in lock_data.items():
            result[lock] = {
                "count": len(scores),
                "avg_protection": round(sum(scores) / len(scores), 2),
            }
        return result

    def verify_lock_status(
        self,
    ) -> list[dict[str, Any]]:
        """Return records with no lock or below threshold."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.lock_type == LockType.NONE or r.protection_score < self._protection_threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "resource_name": (r.resource_name),
                        "lock_type": r.lock_type.value,
                        "protection_score": (r.protection_score),
                        "service": r.service,
                    }
                )
        return sorted(
            results,
            key=lambda x: x["protection_score"],
        )

    def audit_protection_gaps(
        self,
    ) -> list[dict[str, Any]]:
        """Group by service, avg protection, sort ascending."""
        svc_scores: dict[str, list[float]] = {}
        for r in self._records:
            svc_scores.setdefault(r.service, []).append(r.protection_score)
        results: list[dict[str, Any]] = []
        for svc, scores in svc_scores.items():
            results.append(
                {
                    "service": svc,
                    "avg_protection": round(sum(scores) / len(scores), 2),
                    "resource_count": len(scores),
                }
            )
        results.sort(key=lambda x: x["avg_protection"])
        return results

    # -- report / stats ---------------------------------

    def generate_report(self) -> ImmutabilityReport:
        by_lock_type: dict[str, int] = {}
        by_policy: dict[str, int] = {}
        by_compliance: dict[str, int] = {}
        for r in self._records:
            by_lock_type[r.lock_type.value] = by_lock_type.get(r.lock_type.value, 0) + 1
            by_policy[r.protection_policy.value] = by_policy.get(r.protection_policy.value, 0) + 1
            by_compliance[r.compliance_requirement.value] = (
                by_compliance.get(r.compliance_requirement.value, 0) + 1
            )
        gap_count = sum(1 for r in self._records if r.protection_score < self._protection_threshold)
        scores = [r.protection_score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gaps = self.verify_lock_status()
        top_gaps = [o["resource_name"] for o in gaps[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(
                f"{gap_count} resource(s) below protection threshold ({self._protection_threshold})"
            )
        if not recs:
            recs.append("Data immutability protections healthy")
        return ImmutabilityReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_protection_score=avg,
            by_lock_type=by_lock_type,
            by_policy=by_policy,
            by_compliance=by_compliance,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("data_immutability.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        lock_dist: dict[str, int] = {}
        for r in self._records:
            key = r.lock_type.value
            lock_dist[key] = lock_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "protection_threshold": (self._protection_threshold),
            "lock_distribution": lock_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
