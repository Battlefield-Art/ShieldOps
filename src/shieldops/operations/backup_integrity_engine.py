"""Backup Integrity Engine —
verify backup integrity, track verification status,
manage storage tier lifecycle."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class BackupType(StrEnum):
    FULL = "full"
    INCREMENTAL = "incremental"
    DIFFERENTIAL = "differential"
    SNAPSHOT = "snapshot"
    CONTINUOUS = "continuous"


class IntegrityStatus(StrEnum):
    VERIFIED = "verified"
    CORRUPTED = "corrupted"
    INCOMPLETE = "incomplete"
    EXPIRED = "expired"
    UNTESTED = "untested"


class StorageTier(StrEnum):
    HOT = "hot"
    WARM = "warm"
    COLD = "cold"
    ARCHIVE = "archive"
    GLACIER = "glacier"


# --- Models ---


class BackupIntegrityRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    backup_id: str = ""
    service_name: str = ""
    backup_type: BackupType = BackupType.FULL
    integrity_status: IntegrityStatus = IntegrityStatus.UNTESTED
    storage_tier: StorageTier = StorageTier.HOT
    size_gb: float = 0.0
    checksum: str = ""
    retention_days: int = 30
    last_verified_at: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class BackupIntegrityAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_name: str = ""
    backup_type: BackupType = BackupType.FULL
    verified_pct: float = 0.0
    corrupted_count: int = 0
    total_size_gb: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class BackupIntegrityReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_verified_pct: float = 0.0
    by_backup_type: dict[str, int] = Field(default_factory=dict)
    by_integrity_status: dict[str, int] = Field(default_factory=dict)
    by_storage_tier: dict[str, int] = Field(default_factory=dict)
    corrupted_backups: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class BackupIntegrityEngine:
    """Verify backup integrity, track verification status,
    manage storage tier lifecycle."""

    def __init__(self, max_records: int = 200000, verification_threshold: float = 95.0) -> None:
        self._max_records = max_records
        self._verification_threshold = verification_threshold
        self._records: list[BackupIntegrityRecord] = []
        self._analyses: dict[str, BackupIntegrityAnalysis] = {}
        logger.info(
            "backup_integrity_engine.init",
            max_records=max_records,
            verification_threshold=verification_threshold,
        )

    def add_record(
        self,
        backup_id: str = "",
        service_name: str = "",
        backup_type: BackupType = BackupType.FULL,
        integrity_status: IntegrityStatus = IntegrityStatus.UNTESTED,
        storage_tier: StorageTier = StorageTier.HOT,
        size_gb: float = 0.0,
        checksum: str = "",
        retention_days: int = 30,
        last_verified_at: float = 0.0,
        description: str = "",
    ) -> BackupIntegrityRecord:
        record = BackupIntegrityRecord(
            backup_id=backup_id,
            service_name=service_name,
            backup_type=backup_type,
            integrity_status=integrity_status,
            storage_tier=storage_tier,
            size_gb=size_gb,
            checksum=checksum,
            retention_days=retention_days,
            last_verified_at=last_verified_at,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "backup_integrity.record_added",
            record_id=record.id,
            backup_id=backup_id,
        )
        return record

    def process(self, key: str) -> BackupIntegrityAnalysis | dict[str, Any]:
        recs = [r for r in self._records if r.service_name == key or r.id == key]
        if not recs:
            return {"status": "not_found", "key": key}
        verified = sum(1 for r in recs if r.integrity_status == IntegrityStatus.VERIFIED)
        corrupted = sum(1 for r in recs if r.integrity_status == IntegrityStatus.CORRUPTED)
        verified_pct = round(verified / len(recs) * 100, 2)
        total_size = round(sum(r.size_gb for r in recs), 2)
        analysis = BackupIntegrityAnalysis(
            service_name=recs[0].service_name,
            backup_type=recs[0].backup_type,
            verified_pct=verified_pct,
            corrupted_count=corrupted,
            total_size_gb=total_size,
            description=(
                f"{recs[0].service_name} verified={verified_pct}% "
                f"corrupted={corrupted} size={total_size}GB"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> BackupIntegrityReport:
        by_type: dict[str, int] = {}
        by_status: dict[str, int] = {}
        by_tier: dict[str, int] = {}
        for r in self._records:
            bt = r.backup_type.value
            by_type[bt] = by_type.get(bt, 0) + 1
            ist = r.integrity_status.value
            by_status[ist] = by_status.get(ist, 0) + 1
            st = r.storage_tier.value
            by_tier[st] = by_tier.get(st, 0) + 1
        verified_vals = [a.verified_pct for a in self._analyses.values()]
        avg_v = round(sum(verified_vals) / len(verified_vals), 2) if verified_vals else 0.0
        corrupted = list(
            {r.backup_id for r in self._records if r.integrity_status == IntegrityStatus.CORRUPTED}
        )[:10]
        recs: list[str] = []
        if corrupted:
            recs.append(f"{len(corrupted)} corrupted backups require attention")
        untested = by_status.get("untested", 0)
        if untested > len(self._records) * 0.2:
            recs.append(f"{untested} backups untested — schedule verification")
        if not recs:
            recs.append("Backup integrity within acceptable bounds")
        return BackupIntegrityReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_verified_pct=avg_v,
            by_backup_type=by_type,
            by_integrity_status=by_status,
            by_storage_tier=by_tier,
            corrupted_backups=corrupted,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        status_dist: dict[str, int] = {}
        for r in self._records:
            k = r.integrity_status.value
            status_dist[k] = status_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "status_distribution": status_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("backup_integrity_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def find_unverified_backups(self) -> list[dict[str, Any]]:
        """Find backups that have not been integrity-verified."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.integrity_status in (
                IntegrityStatus.UNTESTED,
                IntegrityStatus.INCOMPLETE,
            ):
                results.append(
                    {
                        "backup_id": r.backup_id,
                        "service_name": r.service_name,
                        "backup_type": r.backup_type.value,
                        "integrity_status": r.integrity_status.value,
                        "size_gb": r.size_gb,
                        "storage_tier": r.storage_tier.value,
                        "last_verified_at": r.last_verified_at,
                    }
                )
        results.sort(key=lambda x: x["last_verified_at"])
        return results

    def analyze_storage_tier_distribution(self) -> list[dict[str, Any]]:
        """Analyze backup distribution across storage tiers."""
        tier_data: dict[str, dict[str, Any]] = {}
        for r in self._records:
            t = r.storage_tier.value
            tier_data.setdefault(t, {"count": 0, "total_gb": 0.0, "verified": 0})
            tier_data[t]["count"] += 1
            tier_data[t]["total_gb"] += r.size_gb
            if r.integrity_status == IntegrityStatus.VERIFIED:
                tier_data[t]["verified"] += 1
        results: list[dict[str, Any]] = []
        for tier, data in tier_data.items():
            results.append(
                {
                    "storage_tier": tier,
                    "backup_count": data["count"],
                    "total_size_gb": round(data["total_gb"], 2),
                    "verified_count": data["verified"],
                    "verified_pct": round(data["verified"] / data["count"] * 100, 2)
                    if data["count"] > 0
                    else 0.0,
                }
            )
        results.sort(key=lambda x: x["total_size_gb"], reverse=True)
        return results

    def rank_services_by_backup_health(self) -> list[dict[str, Any]]:
        """Rank services by backup health (verified percentage)."""
        svc_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            s = r.service_name
            svc_data.setdefault(s, {"total": 0, "verified": 0, "corrupted": 0})
            svc_data[s]["total"] += 1
            if r.integrity_status == IntegrityStatus.VERIFIED:
                svc_data[s]["verified"] += 1
            if r.integrity_status == IntegrityStatus.CORRUPTED:
                svc_data[s]["corrupted"] += 1
        results: list[dict[str, Any]] = []
        for svc, data in svc_data.items():
            health = round(data["verified"] / data["total"] * 100, 2) if data["total"] > 0 else 0.0
            results.append(
                {
                    "service_name": svc,
                    "total_backups": data["total"],
                    "verified": data["verified"],
                    "corrupted": data["corrupted"],
                    "health_pct": health,
                    "rank": 0,
                }
            )
        results.sort(key=lambda x: x["health_pct"])
        for idx, entry in enumerate(results, 1):
            entry["rank"] = idx
        return results
