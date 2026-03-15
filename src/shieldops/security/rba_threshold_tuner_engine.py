"""RBA Threshold Tuner Engine —
evaluate threshold effectiveness, recommend threshold adjustments,
simulate threshold changes."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class TuningStrategy(StrEnum):
    VOLUME_BASED = "volume_based"
    FPR_BASED = "fpr_based"
    CAPACITY_BASED = "capacity_based"
    HYBRID = "hybrid"


class ThresholdDirection(StrEnum):
    RAISE_THRESHOLD = "raise_threshold"
    LOWER_THRESHOLD = "lower_threshold"
    HOLD = "hold"
    RESET = "reset"


class TuningOutcome(StrEnum):
    REDUCED_NOISE = "reduced_noise"
    INCREASED_COVERAGE = "increased_coverage"
    NO_EFFECT = "no_effect"
    DEGRADED = "degraded"


# --- Models ---


class ThresholdTunerRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str = ""
    entity_type: str = ""
    tuning_strategy: TuningStrategy = TuningStrategy.HYBRID
    threshold_direction: ThresholdDirection = ThresholdDirection.HOLD
    tuning_outcome: TuningOutcome = TuningOutcome.NO_EFFECT
    current_threshold: float = 0.0
    proposed_threshold: float = 0.0
    false_positive_rate: float = 0.0
    alert_volume: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ThresholdTunerAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str = ""
    tuning_strategy: TuningStrategy = TuningStrategy.HYBRID
    threshold_direction: ThresholdDirection = ThresholdDirection.HOLD
    effectiveness_score: float = 0.0
    adjustment_recommended: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ThresholdTunerReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_false_positive_rate: float = 0.0
    by_tuning_strategy: dict[str, int] = Field(default_factory=dict)
    by_threshold_direction: dict[str, int] = Field(default_factory=dict)
    by_tuning_outcome: dict[str, int] = Field(default_factory=dict)
    high_fpr_rule_ids: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class RbaThresholdTunerEngine:
    """Evaluate threshold effectiveness, recommend threshold adjustments,
    simulate threshold changes."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[ThresholdTunerRecord] = []
        self._analyses: dict[str, ThresholdTunerAnalysis] = {}
        logger.info("rba_threshold_tuner_engine.init", max_records=max_records)

    def add_record(
        self,
        rule_id: str = "",
        entity_type: str = "",
        tuning_strategy: TuningStrategy = TuningStrategy.HYBRID,
        threshold_direction: ThresholdDirection = ThresholdDirection.HOLD,
        tuning_outcome: TuningOutcome = TuningOutcome.NO_EFFECT,
        current_threshold: float = 0.0,
        proposed_threshold: float = 0.0,
        false_positive_rate: float = 0.0,
        alert_volume: int = 0,
        description: str = "",
    ) -> ThresholdTunerRecord:
        record = ThresholdTunerRecord(
            rule_id=rule_id,
            entity_type=entity_type,
            tuning_strategy=tuning_strategy,
            threshold_direction=threshold_direction,
            tuning_outcome=tuning_outcome,
            current_threshold=current_threshold,
            proposed_threshold=proposed_threshold,
            false_positive_rate=false_positive_rate,
            alert_volume=alert_volume,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "threshold_tuner.record_added",
            record_id=record.id,
            rule_id=rule_id,
        )
        return record

    def process(self, key: str) -> ThresholdTunerAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        effectiveness = round(max(0.0, 1.0 - rec.false_positive_rate) * 100, 2)
        adjustment_needed = (
            rec.false_positive_rate > 0.3 or rec.tuning_outcome == TuningOutcome.DEGRADED
        )
        analysis = ThresholdTunerAnalysis(
            rule_id=rec.rule_id,
            tuning_strategy=rec.tuning_strategy,
            threshold_direction=rec.threshold_direction,
            effectiveness_score=effectiveness,
            adjustment_recommended=adjustment_needed,
            description=f"Rule {rec.rule_id} effectiveness={effectiveness}%",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> ThresholdTunerReport:
        by_ts: dict[str, int] = {}
        by_td: dict[str, int] = {}
        by_to: dict[str, int] = {}
        fprs: list[float] = []
        for r in self._records:
            by_ts[r.tuning_strategy.value] = by_ts.get(r.tuning_strategy.value, 0) + 1
            by_td[r.threshold_direction.value] = by_td.get(r.threshold_direction.value, 0) + 1
            by_to[r.tuning_outcome.value] = by_to.get(r.tuning_outcome.value, 0) + 1
            fprs.append(r.false_positive_rate)
        avg_fpr = round(sum(fprs) / len(fprs), 4) if fprs else 0.0
        high_fpr = list(
            {r.rule_id for r in self._records if r.false_positive_rate > 0.3 and r.rule_id}
        )[:10]
        recs: list[str] = []
        if high_fpr:
            recs.append(f"{len(high_fpr)} rules with high false positive rate")
        if not recs:
            recs.append("Threshold tuning within acceptable parameters")
        return ThresholdTunerReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_false_positive_rate=avg_fpr,
            by_tuning_strategy=by_ts,
            by_threshold_direction=by_td,
            by_tuning_outcome=by_to,
            high_fpr_rule_ids=high_fpr,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        ts_dist: dict[str, int] = {}
        for r in self._records:
            ts_dist[r.tuning_strategy.value] = ts_dist.get(r.tuning_strategy.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "tuning_strategy_distribution": ts_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("rba_threshold_tuner_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def evaluate_threshold_effectiveness(self) -> list[dict[str, Any]]:
        """Evaluate threshold effectiveness per rule based on FPR and outcome."""
        rule_data: dict[str, list[ThresholdTunerRecord]] = {}
        for r in self._records:
            rule_data.setdefault(r.rule_id, []).append(r)
        results: list[dict[str, Any]] = []
        for rid, recs in rule_data.items():
            avg_fpr = round(sum(r.false_positive_rate for r in recs) / len(recs), 4)
            degraded_count = sum(1 for r in recs if r.tuning_outcome == TuningOutcome.DEGRADED)
            effectiveness = round(max(0.0, 1.0 - avg_fpr) * 100, 2)
            results.append(
                {
                    "rule_id": rid,
                    "avg_false_positive_rate": avg_fpr,
                    "effectiveness_pct": effectiveness,
                    "degraded_count": degraded_count,
                    "sample_count": len(recs),
                    "needs_tuning": avg_fpr > 0.3,
                }
            )
        results.sort(key=lambda x: x["effectiveness_pct"])
        return results

    def recommend_threshold_adjustments(self) -> list[dict[str, Any]]:
        """Recommend raise or lower for each rule's threshold."""
        rule_latest: dict[str, ThresholdTunerRecord] = {}
        for r in self._records:
            rule_latest[r.rule_id] = r
        results: list[dict[str, Any]] = []
        for rid, rec in rule_latest.items():
            if rec.false_positive_rate > 0.4:
                direction = ThresholdDirection.RAISE_THRESHOLD
                delta = round(rec.current_threshold * 0.1, 2)
            elif rec.false_positive_rate < 0.05 and rec.alert_volume < 10:
                direction = ThresholdDirection.LOWER_THRESHOLD
                delta = round(rec.current_threshold * 0.05, 2)
            else:
                direction = ThresholdDirection.HOLD
                delta = 0.0
            proposed = round(
                rec.current_threshold + delta
                if direction == ThresholdDirection.LOWER_THRESHOLD
                else rec.current_threshold - delta
                if direction == ThresholdDirection.RAISE_THRESHOLD
                else rec.current_threshold,
                2,
            )
            results.append(
                {
                    "rule_id": rid,
                    "current_threshold": rec.current_threshold,
                    "proposed_threshold": proposed,
                    "recommended_direction": direction.value,
                    "false_positive_rate": rec.false_positive_rate,
                    "alert_volume": rec.alert_volume,
                }
            )
        results.sort(key=lambda x: x["false_positive_rate"], reverse=True)
        return results

    def simulate_threshold_change(self, rule_id: str, new_threshold: float) -> dict[str, Any]:
        """Simulate impact of applying a new threshold for a given rule."""
        recs = [r for r in self._records if r.rule_id == rule_id]
        if not recs:
            return {"status": "no_data", "rule_id": rule_id}
        current_avg = round(sum(r.current_threshold for r in recs) / len(recs), 4)
        above_new = sum(1 for r in recs if r.current_threshold < new_threshold)
        below_new = len(recs) - above_new
        suppression_pct = round(above_new / len(recs) * 100, 2) if recs else 0.0
        return {
            "rule_id": rule_id,
            "current_avg_threshold": current_avg,
            "simulated_threshold": new_threshold,
            "alerts_suppressed": above_new,
            "alerts_passed": below_new,
            "suppression_pct": suppression_pct,
            "net_impact": "noise_reduction" if suppression_pct > 20 else "minimal",
        }
