"""Risk Factor Decay Engine —
apply decay schedules to risk factors, detect decay anomalies,
optimize decay parameters."""

from __future__ import annotations

import math
import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class DecayCurve(StrEnum):
    LINEAR = "linear"
    EXPONENTIAL = "exponential"
    STEP_FUNCTION = "step_function"
    SIGMOID = "sigmoid"


class DecayTrigger(StrEnum):
    TIME_ELAPSED = "time_elapsed"
    NEW_EVIDENCE = "new_evidence"
    MANUAL_RESET = "manual_reset"
    CONTEXT_CHANGE = "context_change"


class DecayHealth(StrEnum):
    ACTIVE = "active"
    DECAYING = "decaying"
    NEAR_ZERO = "near_zero"
    EXPIRED = "expired"


# --- Models ---


class RiskDecayRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    factor_id: str = ""
    entity_id: str = ""
    decay_curve: DecayCurve = DecayCurve.EXPONENTIAL
    decay_trigger: DecayTrigger = DecayTrigger.TIME_ELAPSED
    decay_health: DecayHealth = DecayHealth.ACTIVE
    initial_risk: float = 0.0
    current_risk: float = 0.0
    decay_rate: float = 0.0
    age_hours: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class RiskDecayAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    factor_id: str = ""
    decay_curve: DecayCurve = DecayCurve.EXPONENTIAL
    projected_risk: float = 0.0
    time_to_zero_hours: float = 0.0
    anomaly_detected: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class RiskDecayReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_current_risk: float = 0.0
    by_decay_curve: dict[str, int] = Field(default_factory=dict)
    by_decay_trigger: dict[str, int] = Field(default_factory=dict)
    by_decay_health: dict[str, int] = Field(default_factory=dict)
    expired_factor_ids: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class RiskFactorDecayEngine:
    """Apply decay schedules to risk factors, detect decay anomalies,
    optimize decay parameters."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[RiskDecayRecord] = []
        self._analyses: dict[str, RiskDecayAnalysis] = {}
        logger.info("risk_factor_decay_engine.init", max_records=max_records)

    def add_record(
        self,
        factor_id: str = "",
        entity_id: str = "",
        decay_curve: DecayCurve = DecayCurve.EXPONENTIAL,
        decay_trigger: DecayTrigger = DecayTrigger.TIME_ELAPSED,
        decay_health: DecayHealth = DecayHealth.ACTIVE,
        initial_risk: float = 0.0,
        current_risk: float = 0.0,
        decay_rate: float = 0.0,
        age_hours: float = 0.0,
        description: str = "",
    ) -> RiskDecayRecord:
        record = RiskDecayRecord(
            factor_id=factor_id,
            entity_id=entity_id,
            decay_curve=decay_curve,
            decay_trigger=decay_trigger,
            decay_health=decay_health,
            initial_risk=initial_risk,
            current_risk=current_risk,
            decay_rate=decay_rate,
            age_hours=age_hours,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "risk_decay.record_added",
            record_id=record.id,
            factor_id=factor_id,
        )
        return record

    def process(self, key: str) -> RiskDecayAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        projected = self._apply_curve(
            rec.decay_curve, rec.current_risk, rec.decay_rate, rec.age_hours + 24
        )
        time_to_zero = (
            rec.current_risk / rec.decay_rate
            if rec.decay_rate > 0 and rec.decay_curve == DecayCurve.LINEAR
            else 0.0
        )
        anomaly = rec.current_risk > rec.initial_risk
        analysis = RiskDecayAnalysis(
            factor_id=rec.factor_id,
            decay_curve=rec.decay_curve,
            projected_risk=round(projected, 4),
            time_to_zero_hours=round(time_to_zero, 2),
            anomaly_detected=anomaly,
            description=f"Factor {rec.factor_id} projected risk={projected:.4f}",
        )
        self._analyses[key] = analysis
        return analysis

    @staticmethod
    def _apply_curve(
        curve: DecayCurve,
        current: float,
        rate: float,
        hours: float,
    ) -> float:
        if curve == DecayCurve.LINEAR:
            return max(0.0, current - rate * hours)
        if curve == DecayCurve.EXPONENTIAL:
            return current * math.exp(-rate * hours) if rate > 0 else current
        if curve == DecayCurve.STEP_FUNCTION:
            steps = int(hours / 24)
            return max(0.0, current - rate * steps)
        if curve == DecayCurve.SIGMOID:
            midpoint = 48.0
            k = 0.1
            factor = 1.0 / (1.0 + math.exp(-k * (hours - midpoint)))
            return current * (1.0 - factor)
        return current

    def generate_report(self) -> RiskDecayReport:
        by_dc: dict[str, int] = {}
        by_dt: dict[str, int] = {}
        by_dh: dict[str, int] = {}
        risks: list[float] = []
        expired_ids: list[str] = []
        for r in self._records:
            by_dc[r.decay_curve.value] = by_dc.get(r.decay_curve.value, 0) + 1
            by_dt[r.decay_trigger.value] = by_dt.get(r.decay_trigger.value, 0) + 1
            by_dh[r.decay_health.value] = by_dh.get(r.decay_health.value, 0) + 1
            risks.append(r.current_risk)
            if (
                r.decay_health == DecayHealth.EXPIRED
                and r.factor_id
                and r.factor_id not in expired_ids
            ):
                expired_ids.append(r.factor_id)
        avg_r = round(sum(risks) / len(risks), 4) if risks else 0.0
        recs: list[str] = []
        if expired_ids:
            recs.append(f"{len(expired_ids)} risk factors have expired")
        if not recs:
            recs.append("Risk factor decay within normal parameters")
        return RiskDecayReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_current_risk=avg_r,
            by_decay_curve=by_dc,
            by_decay_trigger=by_dt,
            by_decay_health=by_dh,
            expired_factor_ids=expired_ids[:10],
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dc_dist: dict[str, int] = {}
        for r in self._records:
            dc_dist[r.decay_curve.value] = dc_dist.get(r.decay_curve.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "decay_curve_distribution": dc_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("risk_factor_decay_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def apply_decay_schedule(self, projection_hours: float = 24.0) -> list[dict[str, Any]]:
        """Apply decay schedule to all factors and project future risk."""
        factor_latest: dict[str, RiskDecayRecord] = {}
        for r in self._records:
            factor_latest[r.factor_id] = r
        results: list[dict[str, Any]] = []
        for fid, rec in factor_latest.items():
            projected = self._apply_curve(
                rec.decay_curve,
                rec.current_risk,
                rec.decay_rate,
                projection_hours,
            )
            pct_decay = (
                round((rec.current_risk - projected) / rec.current_risk * 100, 2)
                if rec.current_risk > 0
                else 0.0
            )
            results.append(
                {
                    "factor_id": fid,
                    "current_risk": rec.current_risk,
                    "projected_risk": round(projected, 4),
                    "decay_pct": pct_decay,
                    "decay_curve": rec.decay_curve.value,
                    "projection_hours": projection_hours,
                }
            )
        results.sort(key=lambda x: x["projected_risk"], reverse=True)
        return results

    def detect_decay_anomalies(self) -> list[dict[str, Any]]:
        """Detect factors where current risk exceeds initial risk (anti-decay)."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.current_risk > r.initial_risk and r.initial_risk > 0:
                growth = round((r.current_risk - r.initial_risk) / r.initial_risk * 100, 2)
                results.append(
                    {
                        "factor_id": r.factor_id,
                        "entity_id": r.entity_id,
                        "initial_risk": r.initial_risk,
                        "current_risk": r.current_risk,
                        "growth_pct": growth,
                        "decay_trigger": r.decay_trigger.value,
                    }
                )
        results.sort(key=lambda x: x["growth_pct"], reverse=True)
        return results

    def optimize_decay_parameters(self) -> list[dict[str, Any]]:
        """Recommend optimal decay rate per curve type based on observed data."""
        curve_data: dict[str, list[tuple[float, float, float]]] = {}
        for r in self._records:
            curve_data.setdefault(r.decay_curve.value, []).append(
                (r.initial_risk, r.current_risk, r.age_hours)
            )
        results: list[dict[str, Any]] = []
        for curve_name, data_points in curve_data.items():
            valid = [(init, curr, age) for init, curr, age in data_points if init > 0 and age > 0]
            if not valid:
                continue
            avg_decay_rate = sum(
                (init - curr) / (init * age) if init * age > 0 else 0.0 for init, curr, age in valid
            ) / len(valid)
            results.append(
                {
                    "decay_curve": curve_name,
                    "sample_count": len(valid),
                    "recommended_decay_rate": round(max(avg_decay_rate, 0.0), 6),
                    "avg_age_hours": round(sum(age for _, _, age in valid) / len(valid), 2),
                }
            )
        results.sort(key=lambda x: x["recommended_decay_rate"], reverse=True)
        return results
