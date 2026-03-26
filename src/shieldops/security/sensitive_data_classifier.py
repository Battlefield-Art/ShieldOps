"""Sensitive Data Classifier — classify data sensitivity."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class DataRegulation(StrEnum):
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    SOX = "sox"
    CCPA = "ccpa"


class ClassificationMethod(StrEnum):
    REGEX_PATTERN = "regex_pattern"
    ML_CLASSIFIER = "ml_classifier"
    DLP_ENGINE = "dlp_engine"
    MANUAL_TAG = "manual_tag"
    METADATA_SCAN = "metadata_scan"


class SensitivityTier(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"  # noqa: S105


# --- Models ---


class SensitiveDataRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    asset_id: str = ""
    regulation: DataRegulation = DataRegulation.GDPR
    method: ClassificationMethod = ClassificationMethod.REGEX_PATTERN
    tier: SensitivityTier = SensitivityTier.INTERNAL
    data_source: str = ""
    records_scanned: int = 0
    sensitive_fields: int = 0
    exposure_score: float = 0.0
    encrypted: bool = False
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class SensitiveDataAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    asset_id: str = ""
    regulation: DataRegulation = DataRegulation.GDPR
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SensitiveDataReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_exposure_score: float = 0.0
    unencrypted_count: int = 0
    by_regulation: dict[str, int] = Field(default_factory=dict)
    by_method: dict[str, int] = Field(default_factory=dict)
    by_tier: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class SensitiveDataClassifier:
    """Classify sensitive data across sources."""

    def __init__(
        self,
        max_records: int = 200000,
        exposure_threshold: float = 0.6,
    ) -> None:
        self._max_records = max_records
        self._threshold = exposure_threshold
        self._records: list[SensitiveDataRecord] = []
        self._analyses: list[SensitiveDataAnalysis] = []
        logger.info(
            "sensitive_data_classifier.initialized",
            max_records=max_records,
            exposure_threshold=exposure_threshold,
        )

    # -- record / get / list -----------------------------------

    def add_record(
        self,
        asset_id: str,
        regulation: DataRegulation = (DataRegulation.GDPR),
        method: ClassificationMethod = (ClassificationMethod.REGEX_PATTERN),
        tier: SensitivityTier = (SensitivityTier.INTERNAL),
        data_source: str = "",
        records_scanned: int = 0,
        sensitive_fields: int = 0,
        exposure_score: float = 0.0,
        encrypted: bool = False,
        service: str = "",
        team: str = "",
    ) -> SensitiveDataRecord:
        record = SensitiveDataRecord(
            asset_id=asset_id,
            regulation=regulation,
            method=method,
            tier=tier,
            data_source=data_source,
            records_scanned=records_scanned,
            sensitive_fields=sensitive_fields,
            exposure_score=exposure_score,
            encrypted=encrypted,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "sensitive_data_classifier.record_added",
            record_id=record.id,
            asset_id=asset_id,
            regulation=regulation.value,
            tier=tier.value,
        )
        return record

    def get_record(self, record_id: str) -> SensitiveDataRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        regulation: DataRegulation | None = None,
        tier: SensitivityTier | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[SensitiveDataRecord]:
        results = list(self._records)
        if regulation is not None:
            results = [r for r in results if r.regulation == regulation]
        if tier is not None:
            results = [r for r in results if r.tier == tier]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def process(self, asset_id: str) -> SensitiveDataAnalysis:
        matched = [r for r in self._records if r.asset_id == asset_id]
        scores = [r.exposure_score for r in matched]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        breached = avg > self._threshold
        analysis = SensitiveDataAnalysis(
            asset_id=asset_id,
            regulation=(matched[-1].regulation if matched else DataRegulation.GDPR),
            analysis_score=avg,
            threshold=self._threshold,
            breached=breached,
            description=(f"Exposure {avg} for {asset_id}"),
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain operations ------------------------------------

    def classify_content(
        self,
        asset_id: str,
        data_source: str = "",
        method: ClassificationMethod = (ClassificationMethod.REGEX_PATTERN),
        records_scanned: int = 0,
        sensitive_fields: int = 0,
    ) -> dict[str, Any]:
        """Classify content sensitivity."""
        ratio = (
            round(
                sensitive_fields / records_scanned,
                4,
            )
            if records_scanned
            else 0.0
        )
        if ratio > 0.5:
            tier = SensitivityTier.RESTRICTED
        elif ratio > 0.2:
            tier = SensitivityTier.CONFIDENTIAL
        elif ratio > 0.05:
            tier = SensitivityTier.INTERNAL
        else:
            tier = SensitivityTier.PUBLIC
        record = self.add_record(
            asset_id=asset_id,
            data_source=data_source,
            method=method,
            tier=tier,
            records_scanned=records_scanned,
            sensitive_fields=sensitive_fields,
            exposure_score=ratio,
        )
        return {
            "record_id": record.id,
            "asset_id": asset_id,
            "tier": tier.value,
            "sensitive_ratio": ratio,
            "sensitive_fields": sensitive_fields,
        }

    def map_to_regulations(self, asset_id: str) -> dict[str, Any]:
        """Map asset data to applicable regs."""
        matched = [r for r in self._records if r.asset_id == asset_id]
        regs: dict[str, int] = {}
        for r in matched:
            key = r.regulation.value
            regs[key] = regs.get(key, 0) + 1
        high_tier = [
            r
            for r in matched
            if r.tier
            in (
                SensitivityTier.RESTRICTED,
                SensitivityTier.TOP_SECRET,
            )
        ]
        return {
            "asset_id": asset_id,
            "records_found": len(matched),
            "regulations": regs,
            "high_sensitivity_count": len(high_tier),
            "needs_encryption": any(not r.encrypted for r in high_tier),
        }

    def calculate_exposure_risk(
        self,
    ) -> dict[str, Any]:
        """Calculate overall exposure risk."""
        if not self._records:
            return {
                "overall_risk": 0.0,
                "total_assets": 0,
            }
        scores = [r.exposure_score for r in self._records]
        avg = round(sum(scores) / len(scores), 4)
        unencrypted_high = sum(
            1
            for r in self._records
            if not r.encrypted
            and r.tier
            in (
                SensitivityTier.RESTRICTED,
                SensitivityTier.TOP_SECRET,
            )
        )
        by_tier: dict[str, int] = {}
        for r in self._records:
            key = r.tier.value
            by_tier[key] = by_tier.get(key, 0) + 1
        return {
            "overall_risk": avg,
            "total_assets": len(self._records),
            "unencrypted_high_tier": unencrypted_high,
            "above_threshold": avg > self._threshold,
            "by_tier": by_tier,
        }

    # -- report / stats ----------------------------------------

    def generate_report(self) -> SensitiveDataReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.regulation.value] = by_e1.get(r.regulation.value, 0) + 1
            by_e2[r.method.value] = by_e2.get(r.method.value, 0) + 1
            by_e3[r.tier.value] = by_e3.get(r.tier.value, 0) + 1
        scores = [r.exposure_score for r in self._records]
        avg_exp = round(sum(scores) / len(scores), 2) if scores else 0.0
        unenc = sum(1 for r in self._records if not r.encrypted)
        gap_count = sum(1 for r in self._records if r.exposure_score > self._threshold)
        top_gaps = [r.asset_id for r in self._records if r.exposure_score > self._threshold][:5]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} high-exposure asset(s)")
        if unenc > 0:
            recs.append(f"{unenc} unencrypted record(s)")
        if not recs:
            recs.append("Sensitive Data Classifier healthy")
        return SensitiveDataReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_exposure_score=avg_exp,
            unencrypted_count=unenc,
            by_regulation=by_e1,
            by_method=by_e2,
            by_tier=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("sensitive_data_classifier.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.regulation.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "regulation_distribution": e1_dist,
            "unique_assets": len({r.asset_id for r in self._records}),
            "unique_teams": len({r.team for r in self._records}),
        }
