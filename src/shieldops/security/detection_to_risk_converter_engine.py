"""Detection to Risk Converter Engine —
convert detections to risk scores, evaluate source reliability,
detect conversion bias."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class DetectionSource(StrEnum):
    SIEM_RULE = "siem_rule"
    ML_MODEL = "ml_model"
    SIGMA_RULE = "sigma_rule"
    CUSTOM_DETECTION = "custom_detection"


class ConversionQuality(StrEnum):
    HIGH_FIDELITY = "high_fidelity"
    STANDARD = "standard"
    NEEDS_TUNING = "needs_tuning"
    UNRELIABLE = "unreliable"


class RiskContributionType(StrEnum):
    ADDITIVE = "additive"
    MULTIPLICATIVE = "multiplicative"
    CONTEXTUAL = "contextual"
    OVERRIDE = "override"


# --- Models ---


class DetectionRiskRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    detection_id: str = ""
    entity_id: str = ""
    source: DetectionSource = DetectionSource.SIEM_RULE
    conversion_quality: ConversionQuality = ConversionQuality.STANDARD
    contribution_type: RiskContributionType = RiskContributionType.ADDITIVE
    detection_score: float = 0.0
    converted_risk_score: float = 0.0
    source_reliability: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class DetectionRiskAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    detection_id: str = ""
    source: DetectionSource = DetectionSource.SIEM_RULE
    converted_risk: float = 0.0
    quality_rating: str = ""
    bias_detected: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class DetectionRiskReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_converted_risk: float = 0.0
    by_source: dict[str, int] = Field(default_factory=dict)
    by_conversion_quality: dict[str, int] = Field(default_factory=dict)
    by_contribution_type: dict[str, int] = Field(default_factory=dict)
    unreliable_sources: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class DetectionToRiskConverterEngine:
    """Convert detections to risk scores, evaluate source reliability,
    detect conversion bias."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[DetectionRiskRecord] = []
        self._analyses: dict[str, DetectionRiskAnalysis] = {}
        logger.info("detection_to_risk_converter_engine.init", max_records=max_records)

    def add_record(
        self,
        detection_id: str = "",
        entity_id: str = "",
        source: DetectionSource = DetectionSource.SIEM_RULE,
        conversion_quality: ConversionQuality = ConversionQuality.STANDARD,
        contribution_type: RiskContributionType = RiskContributionType.ADDITIVE,
        detection_score: float = 0.0,
        converted_risk_score: float = 0.0,
        source_reliability: float = 0.0,
        description: str = "",
    ) -> DetectionRiskRecord:
        record = DetectionRiskRecord(
            detection_id=detection_id,
            entity_id=entity_id,
            source=source,
            conversion_quality=conversion_quality,
            contribution_type=contribution_type,
            detection_score=detection_score,
            converted_risk_score=converted_risk_score,
            source_reliability=source_reliability,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "detection_risk.record_added",
            record_id=record.id,
            detection_id=detection_id,
        )
        return record

    def process(self, key: str) -> DetectionRiskAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        quality_rating = rec.conversion_quality.value
        bias = abs(rec.converted_risk_score - rec.detection_score) > 30
        analysis = DetectionRiskAnalysis(
            detection_id=rec.detection_id,
            source=rec.source,
            converted_risk=round(rec.converted_risk_score, 4),
            quality_rating=quality_rating,
            bias_detected=bias,
            description=f"Detection {rec.detection_id} converted risk={rec.converted_risk_score}",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> DetectionRiskReport:
        by_src: dict[str, int] = {}
        by_cq: dict[str, int] = {}
        by_ct: dict[str, int] = {}
        risks: list[float] = []
        for r in self._records:
            by_src[r.source.value] = by_src.get(r.source.value, 0) + 1
            by_cq[r.conversion_quality.value] = by_cq.get(r.conversion_quality.value, 0) + 1
            by_ct[r.contribution_type.value] = by_ct.get(r.contribution_type.value, 0) + 1
            risks.append(r.converted_risk_score)
        avg_r = round(sum(risks) / len(risks), 4) if risks else 0.0
        unreliable = list(
            {
                r.source.value
                for r in self._records
                if r.conversion_quality == ConversionQuality.UNRELIABLE
            }
        )
        recs: list[str] = []
        if unreliable:
            recs.append(f"{len(unreliable)} unreliable detection sources found")
        if not recs:
            recs.append("All detection sources meeting quality thresholds")
        return DetectionRiskReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_converted_risk=avg_r,
            by_source=by_src,
            by_conversion_quality=by_cq,
            by_contribution_type=by_ct,
            unreliable_sources=unreliable,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        src_dist: dict[str, int] = {}
        for r in self._records:
            src_dist[r.source.value] = src_dist.get(r.source.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "source_distribution": src_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("detection_to_risk_converter_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def convert_detection_to_risk(self) -> list[dict[str, Any]]:
        """Convert detection scores to risk scores with contribution type logic."""
        entity_risk: dict[str, float] = {}
        entity_contrib: dict[str, list[str]] = {}
        for r in self._records:
            current = entity_risk.get(r.entity_id, 0.0)
            if r.contribution_type == RiskContributionType.ADDITIVE:
                entity_risk[r.entity_id] = current + r.converted_risk_score
            elif r.contribution_type == RiskContributionType.MULTIPLICATIVE:
                base = current if current > 0 else 1.0
                entity_risk[r.entity_id] = base * (1 + r.converted_risk_score / 100)
            elif r.contribution_type == RiskContributionType.OVERRIDE:
                entity_risk[r.entity_id] = r.converted_risk_score
            else:
                entity_risk[r.entity_id] = current + r.converted_risk_score * 0.5
            entity_contrib.setdefault(r.entity_id, []).append(r.detection_id)
        results: list[dict[str, Any]] = []
        for eid, risk in entity_risk.items():
            results.append(
                {
                    "entity_id": eid,
                    "aggregated_risk": round(risk, 4),
                    "detection_count": len(entity_contrib.get(eid, [])),
                }
            )
        results.sort(key=lambda x: x["aggregated_risk"], reverse=True)
        return results

    def evaluate_source_reliability(self) -> list[dict[str, Any]]:
        """Evaluate average reliability per detection source."""
        source_data: dict[str, list[float]] = {}
        source_quality: dict[str, list[str]] = {}
        for r in self._records:
            source_data.setdefault(r.source.value, []).append(r.source_reliability)
            source_quality.setdefault(r.source.value, []).append(r.conversion_quality.value)
        results: list[dict[str, Any]] = []
        for src, reliabilities in source_data.items():
            avg_rel = round(sum(reliabilities) / len(reliabilities), 4)
            qualities = source_quality.get(src, [])
            unreliable_pct = (
                round(
                    qualities.count(ConversionQuality.UNRELIABLE.value) / len(qualities) * 100,
                    2,
                )
                if qualities
                else 0.0
            )
            results.append(
                {
                    "source": src,
                    "avg_reliability": avg_rel,
                    "unreliable_pct": unreliable_pct,
                    "sample_count": len(reliabilities),
                    "needs_tuning": avg_rel < 0.6,
                }
            )
        results.sort(key=lambda x: x["avg_reliability"], reverse=True)
        return results

    def detect_conversion_bias(self, bias_threshold: float = 30.0) -> list[dict[str, Any]]:
        """Detect systematic bias between detection score and converted risk."""
        source_deltas: dict[str, list[float]] = {}
        for r in self._records:
            delta = r.converted_risk_score - r.detection_score
            source_deltas.setdefault(r.source.value, []).append(delta)
        results: list[dict[str, Any]] = []
        for src, deltas in source_deltas.items():
            avg_delta = round(sum(deltas) / len(deltas), 4)
            biased = abs(avg_delta) > bias_threshold
            results.append(
                {
                    "source": src,
                    "avg_conversion_delta": avg_delta,
                    "bias_detected": biased,
                    "over_inflated": avg_delta > bias_threshold,
                    "under_reported": avg_delta < -bias_threshold,
                    "sample_count": len(deltas),
                }
            )
        results.sort(key=lambda x: abs(x["avg_conversion_delta"]), reverse=True)
        return results
