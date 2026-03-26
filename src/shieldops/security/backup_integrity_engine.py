"""BackupIntegrityEngine — Verify backup integrity via checksums and corruption detection."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class IntegrityCheck(StrEnum):
    CHECKSUM = "checksum"
    SIGNATURE = "signature"
    METADATA = "metadata"


class BackupType(StrEnum):
    FULL = "full"
    INCREMENTAL = "incremental"
    DIFFERENTIAL = "differential"


class IntegrityStatus(StrEnum):
    VERIFIED = "verified"
    CORRUPTED = "corrupted"
    TAMPERED = "tampered"
    UNKNOWN = "unknown"


# --- Models ---


class IntegrityRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    integrity_check: IntegrityCheck = IntegrityCheck.CHECKSUM
    backup_type: BackupType = BackupType.FULL
    integrity_status: IntegrityStatus = IntegrityStatus.UNKNOWN
    score: float = 0.0
    backup_size_mb: float = 0.0
    checksum_value: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class IntegrityAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    integrity_check: IntegrityCheck = IntegrityCheck.CHECKSUM
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class IntegrityReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_integrity_check: dict[str, int] = Field(default_factory=dict)
    by_backup_type: dict[str, int] = Field(default_factory=dict)
    by_integrity_status: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class BackupIntegrityEngine:
    """Verify backup integrity via checksums and corruption detection."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[IntegrityRecord] = []
        self._analyses: list[IntegrityAnalysis] = []
        logger.info(
            "backup_integrity_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list -----------------------------------

    def add_record(
        self,
        name: str,
        integrity_check: IntegrityCheck = (IntegrityCheck.CHECKSUM),
        backup_type: BackupType = BackupType.FULL,
        integrity_status: IntegrityStatus = (IntegrityStatus.UNKNOWN),
        score: float = 0.0,
        backup_size_mb: float = 0.0,
        checksum_value: str = "",
        service: str = "",
        team: str = "",
    ) -> IntegrityRecord:
        record = IntegrityRecord(
            name=name,
            integrity_check=integrity_check,
            backup_type=backup_type,
            integrity_status=integrity_status,
            score=score,
            backup_size_mb=backup_size_mb,
            checksum_value=checksum_value,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "backup_integrity_engine.record_added",
            record_id=record.id,
            name=name,
            integrity_check=integrity_check.value,
            backup_type=backup_type.value,
        )
        return record

    def get_record(self, record_id: str) -> IntegrityRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        integrity_check: IntegrityCheck | None = None,
        backup_type: BackupType | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[IntegrityRecord]:
        results = list(self._records)
        if integrity_check is not None:
            results = [r for r in results if r.integrity_check == integrity_check]
        if backup_type is not None:
            results = [r for r in results if r.backup_type == backup_type]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        integrity_check: IntegrityCheck = (IntegrityCheck.CHECKSUM),
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> IntegrityAnalysis:
        analysis = IntegrityAnalysis(
            name=name,
            integrity_check=integrity_check,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "backup_integrity_engine.analysis_added",
            name=name,
            integrity_check=integrity_check.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations -------------------------------------

    def verify_checksum(self) -> list[dict[str, Any]]:
        """Verify checksums across all backup records."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            has_checksum = bool(r.checksum_value)
            is_valid = r.integrity_status == IntegrityStatus.VERIFIED
            results.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "backup_type": r.backup_type.value,
                    "has_checksum": has_checksum,
                    "is_valid": is_valid,
                    "integrity_status": (r.integrity_status.value),
                    "checksum_value": (
                        r.checksum_value[:16] + "..."
                        if len(r.checksum_value) > 16
                        else r.checksum_value
                    ),
                }
            )
        verified = sum(1 for x in results if x["is_valid"])
        total = len(results)
        logger.info(
            "backup_integrity_engine.checksum_verified",
            verified=verified,
            total=total,
        )
        return results

    def detect_corruption(self) -> list[dict[str, Any]]:
        """Detect corrupted or tampered backups."""
        corrupted: list[dict[str, Any]] = []
        for r in self._records:
            if r.integrity_status in (
                IntegrityStatus.CORRUPTED,
                IntegrityStatus.TAMPERED,
            ):
                corrupted.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "backup_type": r.backup_type.value,
                        "integrity_status": (r.integrity_status.value),
                        "score": r.score,
                        "service": r.service,
                        "severity": (
                            "critical" if r.integrity_status == IntegrityStatus.TAMPERED else "high"
                        ),
                        "recommendation": (
                            "Investigate tampering"
                            if r.integrity_status == IntegrityStatus.TAMPERED
                            else "Re-run backup"
                        ),
                    }
                )
        return sorted(
            corrupted,
            key=lambda x: 0 if x["severity"] == "critical" else 1,
        )

    def track_integrity_trend(
        self,
    ) -> list[dict[str, Any]]:
        """Track integrity trends over time by service."""
        svc_data: dict[str, list[IntegrityRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        trends: list[dict[str, Any]] = []
        for svc, records in svc_data.items():
            total = len(records)
            verified = sum(1 for r in records if r.integrity_status == IntegrityStatus.VERIFIED)
            corrupted = sum(1 for r in records if r.integrity_status == IntegrityStatus.CORRUPTED)
            tampered = sum(1 for r in records if r.integrity_status == IntegrityStatus.TAMPERED)
            rate = round(verified / total * 100, 2) if total else 0.0
            trends.append(
                {
                    "service": svc,
                    "total_backups": total,
                    "verified": verified,
                    "corrupted": corrupted,
                    "tampered": tampered,
                    "integrity_rate": rate,
                    "health": (
                        "healthy" if rate >= 95 else ("degraded" if rate >= 80 else "critical")
                    ),
                }
            )
        return sorted(trends, key=lambda x: x["integrity_rate"])

    # -- standard methods --------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.integrity_check.value
            type_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in type_data.items():
            result[k] = {
                "count": len(scores),
                "avg_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_gaps(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "integrity_check": (r.integrity_check.value),
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc_scores: dict[str, list[float]] = {}
        for r in self._records:
            svc_scores.setdefault(r.service, []).append(r.score)
        results: list[dict[str, Any]] = []
        for svc, scores in svc_scores.items():
            results.append(
                {
                    "service": svc,
                    "avg_score": round(sum(scores) / len(scores), 2),
                }
            )
        results.sort(key=lambda x: x["avg_score"])
        return results

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
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats ----------------------------------------

    def generate_report(self) -> IntegrityReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.integrity_check.value] = by_e1.get(r.integrity_check.value, 0) + 1
            by_e2[r.backup_type.value] = by_e2.get(r.backup_type.value, 0) + 1
            by_e3[r.integrity_status.value] = by_e3.get(r.integrity_status.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("Backup Integrity Engine is healthy")
        return IntegrityReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_integrity_check=by_e1,
            by_backup_type=by_e2,
            by_integrity_status=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("backup_integrity_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.integrity_check.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "integrity_check_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
