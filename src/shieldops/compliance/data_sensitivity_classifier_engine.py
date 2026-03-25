"""Data Sensitivity Classifier Engine — track data classification accuracy and coverage."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SensitivityTier(StrEnum):
    TOP_SECRET = "top_secret"  # noqa: S105
    CONFIDENTIAL = "confidential"
    INTERNAL = "internal"
    PUBLIC = "public"
    UNCLASSIFIED = "unclassified"


class DataRegulation(StrEnum):
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    CCPA = "ccpa"
    SOX = "sox"


class ClassificationMethod(StrEnum):
    REGEX = "regex"
    ML_MODEL = "ml_model"
    LLM = "llm"
    MANUAL = "manual"
    INHERITED = "inherited"


# --- Models ---


class DataSensitivityClassifierRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    asset_id: str = ""
    sensitivity_tier: SensitivityTier = SensitivityTier.UNCLASSIFIED
    data_regulation: DataRegulation = DataRegulation.GDPR
    classification_method: ClassificationMethod = ClassificationMethod.REGEX
    confidence: float = 0.0
    records_scanned: int = 0
    findings_count: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class DataSensitivityClassifierAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    asset_id: str = ""
    sensitivity_tier: SensitivityTier = SensitivityTier.UNCLASSIFIED
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class DataSensitivityClassifierReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_sensitivity_tier: dict[str, int] = Field(default_factory=dict)
    by_data_regulation: dict[str, int] = Field(default_factory=dict)
    by_classification_method: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class DataSensitivityClassifierEngine:
    """Track data classification accuracy, coverage, and sensitivity tiers."""

    def __init__(
        self,
        max_records: int = 200000,
        coverage_threshold: float = 90.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = coverage_threshold
        self._records: list[DataSensitivityClassifierRecord] = []
        self._analyses: list[DataSensitivityClassifierAnalysis] = []
        logger.info(
            "data_sensitivity_classifier_engine.initialized",
            max_records=max_records,
            coverage_threshold=coverage_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        asset_id: str,
        sensitivity_tier: SensitivityTier = SensitivityTier.UNCLASSIFIED,
        data_regulation: DataRegulation = DataRegulation.GDPR,
        classification_method: ClassificationMethod = ClassificationMethod.REGEX,
        confidence: float = 0.0,
        records_scanned: int = 0,
        findings_count: int = 0,
        service: str = "",
        team: str = "",
    ) -> DataSensitivityClassifierRecord:
        record = DataSensitivityClassifierRecord(
            asset_id=asset_id,
            sensitivity_tier=sensitivity_tier,
            data_regulation=data_regulation,
            classification_method=classification_method,
            confidence=confidence,
            records_scanned=records_scanned,
            findings_count=findings_count,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "data_sensitivity_classifier_engine.record_added",
            record_id=record.id,
            asset_id=asset_id,
            sensitivity_tier=sensitivity_tier.value,
            data_regulation=data_regulation.value,
        )
        return record

    def get_record(self, record_id: str) -> DataSensitivityClassifierRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        sensitivity_tier: SensitivityTier | None = None,
        data_regulation: DataRegulation | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[DataSensitivityClassifierRecord]:
        results = list(self._records)
        if sensitivity_tier is not None:
            results = [r for r in results if r.sensitivity_tier == sensitivity_tier]
        if data_regulation is not None:
            results = [r for r in results if r.data_regulation == data_regulation]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        asset_id: str,
        sensitivity_tier: SensitivityTier = SensitivityTier.UNCLASSIFIED,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> DataSensitivityClassifierAnalysis:
        analysis = DataSensitivityClassifierAnalysis(
            asset_id=asset_id,
            sensitivity_tier=sensitivity_tier,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "data_sensitivity_classifier_engine.analysis_added",
            asset_id=asset_id,
            sensitivity_tier=sensitivity_tier.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_classification_coverage(self) -> list[dict[str, Any]]:
        """Analyze classification coverage by regulation and method."""
        reg_data: dict[str, list[float]] = {}
        for r in self._records:
            reg_data.setdefault(r.data_regulation.value, []).append(r.confidence)
        results: list[dict[str, Any]] = []
        for reg, confidences in reg_data.items():
            avg_conf = round(sum(confidences) / len(confidences), 2) if confidences else 0.0
            classified = sum(
                1
                for r in self._records
                if r.data_regulation.value == reg
                and r.sensitivity_tier != SensitivityTier.UNCLASSIFIED
            )
            total = len(confidences)
            coverage_pct = round(classified / total * 100, 2) if total > 0 else 0.0
            results.append(
                {
                    "data_regulation": reg,
                    "total_assets": total,
                    "classified_count": classified,
                    "coverage_pct": coverage_pct,
                    "avg_confidence": avg_conf,
                }
            )
        return sorted(results, key=lambda x: x["coverage_pct"])

    def identify_unclassified_assets(self) -> list[dict[str, Any]]:
        """Identify assets that remain unclassified."""
        unclassified: list[dict[str, Any]] = []
        for r in self._records:
            if r.sensitivity_tier == SensitivityTier.UNCLASSIFIED:
                unclassified.append(
                    {
                        "record_id": r.id,
                        "asset_id": r.asset_id,
                        "data_regulation": r.data_regulation.value,
                        "classification_method": r.classification_method.value,
                        "records_scanned": r.records_scanned,
                        "findings_count": r.findings_count,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(unclassified, key=lambda x: x["findings_count"], reverse=True)

    def detect_classification_trends(self) -> list[dict[str, Any]]:
        """Detect trends in classification methods and accuracy."""
        method_data: dict[str, list[float]] = {}
        for r in self._records:
            method_data.setdefault(r.classification_method.value, []).append(r.confidence)
        results: list[dict[str, Any]] = []
        for method, confidences in method_data.items():
            avg = round(sum(confidences) / len(confidences), 2) if confidences else 0.0
            high_conf = sum(1 for c in confidences if c >= self._threshold)
            results.append(
                {
                    "classification_method": method,
                    "total_classifications": len(confidences),
                    "avg_confidence": avg,
                    "high_confidence_count": high_conf,
                    "high_confidence_pct": round(high_conf / len(confidences) * 100, 2)
                    if confidences
                    else 0.0,
                }
            )
        return sorted(results, key=lambda x: x["avg_confidence"], reverse=True)

    # -- standard methods ---------------------------------------------------

    def generate_report(self) -> DataSensitivityClassifierReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.sensitivity_tier.value] = by_e1.get(r.sensitivity_tier.value, 0) + 1
            by_e2[r.data_regulation.value] = by_e2.get(r.data_regulation.value, 0) + 1
            by_e3[r.classification_method.value] = by_e3.get(r.classification_method.value, 0) + 1
        scores = [r.confidence for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        unclassified = self.identify_unclassified_assets()
        gap_count = len(unclassified)
        top_gaps = [o["asset_id"] for o in unclassified[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} asset(s) remain unclassified")
        if avg_score < self._threshold:
            recs.append(f"Avg confidence {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("Data Sensitivity Classifier Engine is healthy")
        return DataSensitivityClassifierReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_sensitivity_tier=by_e1,
            by_data_regulation=by_e2,
            by_classification_method=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("data_sensitivity_classifier_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.sensitivity_tier.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "coverage_threshold": self._threshold,
            "sensitivity_tier_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
