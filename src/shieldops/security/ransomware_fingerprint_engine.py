"""Ransomware Fingerprint Engine — variant identification and encryption tracking."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class EncryptionPattern(StrEnum):
    AES_256 = "aes_256"
    RSA_2048 = "rsa_2048"
    CHACHA20 = "chacha20"
    HYBRID = "hybrid"
    UNKNOWN = "unknown"


class RansomwareFamily(StrEnum):
    LOCKBIT = "lockbit"
    BLACKCAT = "blackcat"
    CLOP = "clop"
    ROYAL = "royal"
    UNKNOWN = "unknown"


class InfectionStage(StrEnum):
    INITIAL_ACCESS = "initial_access"
    LATERAL_MOVEMENT = "lateral_movement"
    ENCRYPTION_ACTIVE = "encryption_active"
    EXFILTRATION = "exfiltration"
    COMPLETE = "complete"


# --- Models ---


class FingerprintRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    fingerprint_name: str = ""
    encryption_pattern: EncryptionPattern = EncryptionPattern.UNKNOWN
    ransomware_family: RansomwareFamily = RansomwareFamily.UNKNOWN
    infection_stage: InfectionStage = InfectionStage.INITIAL_ACCESS
    confidence_score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class FingerprintAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    fingerprint_name: str = ""
    encryption_pattern: EncryptionPattern = EncryptionPattern.UNKNOWN
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class FingerprintReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    high_risk_count: int = 0
    avg_confidence_score: float = 0.0
    by_pattern: dict[str, int] = Field(default_factory=dict)
    by_family: dict[str, int] = Field(default_factory=dict)
    by_stage: dict[str, int] = Field(default_factory=dict)
    top_high_risk: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class RansomwareFingerprintEngine:
    """Ransomware variant fingerprinting and encryption spread tracking."""

    def __init__(
        self,
        max_records: int = 200000,
        confidence_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._confidence_threshold = confidence_threshold
        self._records: list[FingerprintRecord] = []
        self._analyses: list[FingerprintAnalysis] = []
        logger.info(
            "ransomware_fingerprint.initialized",
            max_records=max_records,
            confidence_threshold=confidence_threshold,
        )

    # -- record / get / list ----------------------------

    def add_record(
        self,
        fingerprint_name: str,
        encryption_pattern: EncryptionPattern = (EncryptionPattern.UNKNOWN),
        ransomware_family: RansomwareFamily = (RansomwareFamily.UNKNOWN),
        infection_stage: InfectionStage = (InfectionStage.INITIAL_ACCESS),
        confidence_score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> FingerprintRecord:
        record = FingerprintRecord(
            fingerprint_name=fingerprint_name,
            encryption_pattern=encryption_pattern,
            ransomware_family=ransomware_family,
            infection_stage=infection_stage,
            confidence_score=confidence_score,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "ransomware_fingerprint.record_added",
            record_id=record.id,
            fingerprint_name=fingerprint_name,
            encryption_pattern=encryption_pattern.value,
            ransomware_family=ransomware_family.value,
        )
        return record

    def get_record(self, record_id: str) -> FingerprintRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        encryption_pattern: EncryptionPattern | None = None,
        ransomware_family: RansomwareFamily | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[FingerprintRecord]:
        results = list(self._records)
        if encryption_pattern is not None:
            results = [r for r in results if r.encryption_pattern == encryption_pattern]
        if ransomware_family is not None:
            results = [r for r in results if r.ransomware_family == ransomware_family]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        fingerprint_name: str,
        encryption_pattern: EncryptionPattern = (EncryptionPattern.UNKNOWN),
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> FingerprintAnalysis:
        analysis = FingerprintAnalysis(
            fingerprint_name=fingerprint_name,
            encryption_pattern=encryption_pattern,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "ransomware_fingerprint.analysis_added",
            fingerprint_name=fingerprint_name,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations ------------------------------

    def fingerprint_variant(self) -> dict[str, Any]:
        """Group by ransomware_family; return count and avg confidence."""
        family_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.ransomware_family.value
            family_data.setdefault(key, []).append(r.confidence_score)
        result: dict[str, Any] = {}
        for family, scores in family_data.items():
            result[family] = {
                "count": len(scores),
                "avg_confidence": round(sum(scores) / len(scores), 2),
            }
        return result

    def track_encryption_spread(
        self,
    ) -> list[dict[str, Any]]:
        """Return records in active encryption stages."""
        active = [
            InfectionStage.ENCRYPTION_ACTIVE,
            InfectionStage.EXFILTRATION,
        ]
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.infection_stage in active:
                results.append(
                    {
                        "record_id": r.id,
                        "fingerprint_name": r.fingerprint_name,
                        "encryption_pattern": (r.encryption_pattern.value),
                        "infection_stage": (r.infection_stage.value),
                        "confidence_score": (r.confidence_score),
                        "service": r.service,
                    }
                )
        return sorted(
            results,
            key=lambda x: x["confidence_score"],
            reverse=True,
        )

    def predict_next_target(
        self,
    ) -> list[dict[str, Any]]:
        """Group by service, rank by frequency of early-stage hits."""
        svc_counts: dict[str, int] = {}
        early = [
            InfectionStage.INITIAL_ACCESS,
            InfectionStage.LATERAL_MOVEMENT,
        ]
        for r in self._records:
            if r.infection_stage in early:
                svc_counts[r.service] = svc_counts.get(r.service, 0) + 1
        results = [{"service": svc, "early_stage_count": cnt} for svc, cnt in svc_counts.items()]
        results.sort(
            key=lambda x: int(str(x["early_stage_count"])),
            reverse=True,
        )
        return results

    # -- report / stats ---------------------------------

    def generate_report(self) -> FingerprintReport:
        by_pattern: dict[str, int] = {}
        by_family: dict[str, int] = {}
        by_stage: dict[str, int] = {}
        for r in self._records:
            by_pattern[r.encryption_pattern.value] = (
                by_pattern.get(r.encryption_pattern.value, 0) + 1
            )
            by_family[r.ransomware_family.value] = by_family.get(r.ransomware_family.value, 0) + 1
            by_stage[r.infection_stage.value] = by_stage.get(r.infection_stage.value, 0) + 1
        high_risk_count = sum(
            1 for r in self._records if r.confidence_score >= self._confidence_threshold
        )
        scores = [r.confidence_score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        top = [
            r.fingerprint_name
            for r in sorted(
                self._records,
                key=lambda x: x.confidence_score,
                reverse=True,
            )[:5]
        ]
        recs: list[str] = []
        if high_risk_count > 0:
            recs.append(f"{high_risk_count} high-confidence ransomware fingerprint(s) detected")
        if not recs:
            recs.append("No high-confidence ransomware detected")
        return FingerprintReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            high_risk_count=high_risk_count,
            avg_confidence_score=avg,
            by_pattern=by_pattern,
            by_family=by_family,
            by_stage=by_stage,
            top_high_risk=top,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("ransomware_fingerprint.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        family_dist: dict[str, int] = {}
        for r in self._records:
            key = r.ransomware_family.value
            family_dist[key] = family_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "confidence_threshold": (self._confidence_threshold),
            "family_distribution": family_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
