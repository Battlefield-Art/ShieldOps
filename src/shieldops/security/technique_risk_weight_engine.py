"""Technique Risk Weight Engine —
calibrate MITRE technique risk weights, detect staleness,
compare weights to industry baselines."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class TechniqueCategory(StrEnum):
    INITIAL_ACCESS = "initial_access"
    LATERAL_MOVEMENT = "lateral_movement"
    EXFILTRATION = "exfiltration"
    PERSISTENCE = "persistence"


class WeightCalibration(StrEnum):
    STATIC = "static"
    ENVIRONMENT_ADJUSTED = "environment_adjusted"
    THREAT_INTEL_DRIVEN = "threat_intel_driven"
    ML_CALIBRATED = "ml_calibrated"


class TechniquePrevalence(StrEnum):
    COMMON = "common"
    EMERGING = "emerging"
    RARE = "rare"
    NOVEL = "novel"


# --- Models ---


class TechniqueRiskWeightRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    technique_id: str = ""
    technique_name: str = ""
    category: TechniqueCategory = TechniqueCategory.INITIAL_ACCESS
    calibration: WeightCalibration = WeightCalibration.STATIC
    prevalence: TechniquePrevalence = TechniquePrevalence.COMMON
    risk_weight: float = 0.0
    industry_baseline: float = 0.0
    last_calibrated_at: float = Field(default_factory=time.time)
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class TechniqueRiskWeightAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    technique_id: str = ""
    calibration: WeightCalibration = WeightCalibration.STATIC
    weight_delta: float = 0.0
    is_stale: bool = False
    deviation_from_industry: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class TechniqueRiskWeightReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_risk_weight: float = 0.0
    by_category: dict[str, int] = Field(default_factory=dict)
    by_calibration: dict[str, int] = Field(default_factory=dict)
    by_prevalence: dict[str, int] = Field(default_factory=dict)
    stale_technique_ids: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class TechniqueRiskWeightEngine:
    """Calibrate MITRE technique risk weights, detect staleness,
    compare weights to industry baselines."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[TechniqueRiskWeightRecord] = []
        self._analyses: dict[str, TechniqueRiskWeightAnalysis] = {}
        logger.info("technique_risk_weight_engine.init", max_records=max_records)

    def add_record(
        self,
        technique_id: str = "",
        technique_name: str = "",
        category: TechniqueCategory = TechniqueCategory.INITIAL_ACCESS,
        calibration: WeightCalibration = WeightCalibration.STATIC,
        prevalence: TechniquePrevalence = TechniquePrevalence.COMMON,
        risk_weight: float = 0.0,
        industry_baseline: float = 0.0,
        last_calibrated_at: float = 0.0,
        description: str = "",
    ) -> TechniqueRiskWeightRecord:
        record = TechniqueRiskWeightRecord(
            technique_id=technique_id,
            technique_name=technique_name,
            category=category,
            calibration=calibration,
            prevalence=prevalence,
            risk_weight=risk_weight,
            industry_baseline=industry_baseline,
            last_calibrated_at=last_calibrated_at or time.time(),
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "technique_risk_weight.record_added",
            record_id=record.id,
            technique_id=technique_id,
        )
        return record

    def process(self, key: str) -> TechniqueRiskWeightAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        stale_threshold = 86400 * 30  # 30 days
        is_stale = (time.time() - rec.last_calibrated_at) > stale_threshold
        deviation = round(rec.risk_weight - rec.industry_baseline, 4)
        analysis = TechniqueRiskWeightAnalysis(
            technique_id=rec.technique_id,
            calibration=rec.calibration,
            weight_delta=round(rec.risk_weight, 4),
            is_stale=is_stale,
            deviation_from_industry=deviation,
            description=f"Technique {rec.technique_id} weight={rec.risk_weight}",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> TechniqueRiskWeightReport:
        by_cat: dict[str, int] = {}
        by_cal: dict[str, int] = {}
        by_prev: dict[str, int] = {}
        weights: list[float] = []
        stale_ids: list[str] = []
        stale_threshold = 86400 * 30
        for r in self._records:
            by_cat[r.category.value] = by_cat.get(r.category.value, 0) + 1
            by_cal[r.calibration.value] = by_cal.get(r.calibration.value, 0) + 1
            by_prev[r.prevalence.value] = by_prev.get(r.prevalence.value, 0) + 1
            weights.append(r.risk_weight)
            if (
                (time.time() - r.last_calibrated_at) > stale_threshold
                and r.technique_id
                and r.technique_id not in stale_ids
            ):
                stale_ids.append(r.technique_id)
        avg_w = round(sum(weights) / len(weights), 4) if weights else 0.0
        recs: list[str] = []
        if stale_ids:
            recs.append(f"{len(stale_ids)} techniques have stale weights")
        if not recs:
            recs.append("All technique weights are current")
        return TechniqueRiskWeightReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_risk_weight=avg_w,
            by_category=by_cat,
            by_calibration=by_cal,
            by_prevalence=by_prev,
            stale_technique_ids=stale_ids[:10],
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        cat_dist: dict[str, int] = {}
        for r in self._records:
            cat_dist[r.category.value] = cat_dist.get(r.category.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "category_distribution": cat_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("technique_risk_weight_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def calibrate_technique_weights(self) -> list[dict[str, Any]]:
        """Calibrate risk weights per technique using prevalence multipliers."""
        prev_mult = {
            TechniquePrevalence.COMMON: 1.0,
            TechniquePrevalence.EMERGING: 1.25,
            TechniquePrevalence.RARE: 0.75,
            TechniquePrevalence.NOVEL: 1.5,
        }
        tech_data: dict[str, list[TechniqueRiskWeightRecord]] = {}
        for r in self._records:
            tech_data.setdefault(r.technique_id, []).append(r)
        results: list[dict[str, Any]] = []
        for tid, recs in tech_data.items():
            latest = recs[-1]
            mult = prev_mult.get(latest.prevalence, 1.0)
            calibrated = round(latest.risk_weight * mult, 4)
            results.append(
                {
                    "technique_id": tid,
                    "original_weight": latest.risk_weight,
                    "calibrated_weight": calibrated,
                    "calibration_method": latest.calibration.value,
                    "prevalence": latest.prevalence.value,
                    "samples": len(recs),
                }
            )
        results.sort(key=lambda x: x["calibrated_weight"], reverse=True)
        return results

    def detect_weight_staleness(self, staleness_days: int = 30) -> list[dict[str, Any]]:
        """Detect techniques whose weights have not been recalibrated recently."""
        now = time.time()
        tech_latest: dict[str, TechniqueRiskWeightRecord] = {}
        for r in self._records:
            tech_latest[r.technique_id] = r
        results: list[dict[str, Any]] = []
        for tid, rec in tech_latest.items():
            age_days = round((now - rec.last_calibrated_at) / 86400, 2)
            is_stale = age_days > staleness_days
            if is_stale:
                results.append(
                    {
                        "technique_id": tid,
                        "last_calibrated_days_ago": age_days,
                        "staleness_threshold_days": staleness_days,
                        "calibration": rec.calibration.value,
                        "risk_weight": rec.risk_weight,
                    }
                )
        results.sort(key=lambda x: x["last_calibrated_days_ago"], reverse=True)
        return results

    def compare_weights_to_industry(self) -> list[dict[str, Any]]:
        """Compare technique risk weights against industry baseline values."""
        tech_latest: dict[str, TechniqueRiskWeightRecord] = {}
        for r in self._records:
            tech_latest[r.technique_id] = r
        results: list[dict[str, Any]] = []
        for tid, rec in tech_latest.items():
            delta = round(rec.risk_weight - rec.industry_baseline, 4)
            pct = (
                round(delta / rec.industry_baseline * 100, 2) if rec.industry_baseline != 0 else 0.0
            )
            results.append(
                {
                    "technique_id": tid,
                    "risk_weight": rec.risk_weight,
                    "industry_baseline": rec.industry_baseline,
                    "delta": delta,
                    "deviation_pct": pct,
                    "overweighted": delta > 0,
                }
            )
        results.sort(key=lambda x: abs(x["delta"]), reverse=True)
        return results
