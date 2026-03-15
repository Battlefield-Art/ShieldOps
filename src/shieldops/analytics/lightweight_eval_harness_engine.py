"""Lightweight Eval Harness Engine —
select eval mode, estimate accuracy,
and calibrate proxy metrics."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class EvalMode(StrEnum):
    FULL_SUITE = "full_suite"
    SAMPLED_SUITE = "sampled_suite"
    PROXY_METRIC = "proxy_metric"
    FAST_CHECK = "fast_check"


class EvalReliability(StrEnum):
    DEFINITIVE = "definitive"
    HIGH_CONFIDENCE = "high_confidence"
    INDICATIVE = "indicative"
    NOISY = "noisy"


class EvalCost(StrEnum):
    EXPENSIVE = "expensive"
    MODERATE = "moderate"
    CHEAP = "cheap"
    FREE = "free"


# --- Models ---


class LightweightEvalRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    experiment_id: str = ""
    eval_mode: EvalMode = EvalMode.FAST_CHECK
    reliability: EvalReliability = EvalReliability.HIGH_CONFIDENCE
    eval_cost: EvalCost = EvalCost.CHEAP
    eval_score: float = 0.0
    proxy_score: float = 0.0
    duration_seconds: float = 0.0
    sample_fraction: float = 1.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class LightweightEvalAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    experiment_id: str = ""
    recommended_mode: EvalMode = EvalMode.FAST_CHECK
    proxy_accuracy_pct: float = 0.0
    cost_efficiency_score: float = 0.0
    reliability: EvalReliability = EvalReliability.HIGH_CONFIDENCE
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class LightweightEvalReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    by_eval_mode: dict[str, int] = Field(default_factory=dict)
    by_reliability: dict[str, int] = Field(default_factory=dict)
    by_eval_cost: dict[str, int] = Field(default_factory=dict)
    top_efficient: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class LightweightEvalHarnessEngine:
    """Select eval mode, estimate eval accuracy,
    and calibrate proxy metrics."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[LightweightEvalRecord] = []
        self._analyses: dict[str, LightweightEvalAnalysis] = {}
        logger.info(
            "lightweight_eval_harness.init",
            max_records=max_records,
        )

    def add_record(
        self,
        experiment_id: str = "",
        eval_mode: EvalMode = EvalMode.FAST_CHECK,
        reliability: EvalReliability = EvalReliability.HIGH_CONFIDENCE,
        eval_cost: EvalCost = EvalCost.CHEAP,
        eval_score: float = 0.0,
        proxy_score: float = 0.0,
        duration_seconds: float = 0.0,
        sample_fraction: float = 1.0,
        description: str = "",
    ) -> LightweightEvalRecord:
        record = LightweightEvalRecord(
            experiment_id=experiment_id,
            eval_mode=eval_mode,
            reliability=reliability,
            eval_cost=eval_cost,
            eval_score=eval_score,
            proxy_score=proxy_score,
            duration_seconds=duration_seconds,
            sample_fraction=sample_fraction,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "lightweight_eval.record_added",
            record_id=record.id,
            experiment_id=experiment_id,
        )
        return record

    def process(self, key: str) -> LightweightEvalAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        proxy_err = abs(rec.proxy_score - rec.eval_score)
        proxy_accuracy = round(max(0.0, 100.0 - proxy_err * 100.0), 2)
        cost_map = {
            EvalCost.FREE: 4.0,
            EvalCost.CHEAP: 3.0,
            EvalCost.MODERATE: 2.0,
            EvalCost.EXPENSIVE: 1.0,
        }
        cost_score = cost_map.get(rec.eval_cost, 2.0)
        efficiency = round(rec.eval_score * cost_score, 4) if rec.duration_seconds > 0 else 0.0
        budget_hint = rec.eval_cost in (EvalCost.EXPENSIVE, EvalCost.MODERATE)
        recommended = EvalMode.FAST_CHECK if budget_hint else rec.eval_mode
        analysis = LightweightEvalAnalysis(
            experiment_id=rec.experiment_id,
            recommended_mode=recommended,
            proxy_accuracy_pct=proxy_accuracy,
            cost_efficiency_score=efficiency,
            reliability=rec.reliability,
            description=f"Experiment {rec.experiment_id} proxy_acc={proxy_accuracy}%",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> LightweightEvalReport:
        by_em: dict[str, int] = {}
        by_r: dict[str, int] = {}
        by_ec: dict[str, int] = {}
        for r in self._records:
            by_em[r.eval_mode.value] = by_em.get(r.eval_mode.value, 0) + 1
            by_r[r.reliability.value] = by_r.get(r.reliability.value, 0) + 1
            by_ec[r.eval_cost.value] = by_ec.get(r.eval_cost.value, 0) + 1
        exp_efficiency: dict[str, float] = {}
        for r in self._records:
            if r.duration_seconds > 0:
                eff = r.eval_score / r.duration_seconds
                if r.experiment_id not in exp_efficiency or eff > exp_efficiency[r.experiment_id]:
                    exp_efficiency[r.experiment_id] = eff
        top_efficient = sorted(exp_efficiency, key=lambda x: exp_efficiency[x], reverse=True)[:10]
        recs_list: list[str] = []
        noisy = by_r.get("noisy", 0)
        if noisy > 0:
            recs_list.append(f"{noisy} noisy evaluations — switch to higher-reliability mode")
        expensive = by_ec.get("expensive", 0)
        if expensive > 0:
            recs_list.append(f"{expensive} expensive evals — consider proxy metrics")
        if not recs_list:
            recs_list.append("Eval harness operating efficiently")
        return LightweightEvalReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            by_eval_mode=by_em,
            by_reliability=by_r,
            by_eval_cost=by_ec,
            top_efficient=top_efficient,
            recommendations=recs_list,
        )

    def get_stats(self) -> dict[str, Any]:
        em_dist: dict[str, int] = {}
        for r in self._records:
            em_dist[r.eval_mode.value] = em_dist.get(r.eval_mode.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "eval_mode_distribution": em_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("lightweight_eval_harness.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def select_eval_mode(self, budget_seconds: float, reliability_floor: str) -> dict[str, Any]:
        """Select the best eval mode given budget and reliability floor."""
        reliability_rank = {
            EvalReliability.DEFINITIVE: 4,
            EvalReliability.HIGH_CONFIDENCE: 3,
            EvalReliability.INDICATIVE: 2,
            EvalReliability.NOISY: 1,
        }
        floor_rank = reliability_rank.get(
            EvalReliability(reliability_floor)
            if reliability_floor in [e.value for e in EvalReliability]
            else EvalReliability.INDICATIVE,
            2,
        )
        eligible = [
            r
            for r in self._records
            if r.duration_seconds <= budget_seconds
            and reliability_rank.get(r.reliability, 1) >= floor_rank
        ]
        if not eligible:
            return {
                "recommended_mode": EvalMode.FAST_CHECK.value,
                "reason": "no_eligible_modes",
            }
        best = max(eligible, key=lambda x: x.eval_score / max(x.duration_seconds, 0.001))
        return {
            "recommended_mode": best.eval_mode.value,
            "expected_score": best.eval_score,
            "expected_duration_seconds": best.duration_seconds,
            "reliability": best.reliability.value,
        }

    def estimate_eval_accuracy(self) -> list[dict[str, Any]]:
        """Estimate actual eval accuracy per mode by comparing to full suite."""
        full_suite_recs = [r for r in self._records if r.eval_mode == EvalMode.FULL_SUITE]
        if not full_suite_recs:
            return []
        full_by_exp: dict[str, float] = {}
        for r in full_suite_recs:
            full_by_exp[r.experiment_id] = r.eval_score
        results: list[dict[str, Any]] = []
        mode_data: dict[str, list[float]] = {}
        for r in self._records:
            if r.eval_mode == EvalMode.FULL_SUITE:
                continue
            if r.experiment_id not in full_by_exp:
                continue
            true_score = full_by_exp[r.experiment_id]
            error = abs(r.eval_score - true_score)
            mode_data.setdefault(r.eval_mode.value, []).append(error)
        for mode_name, errors in mode_data.items():
            avg_err = sum(errors) / len(errors)
            accuracy = max(0.0, 100.0 - avg_err * 100.0)
            results.append(
                {
                    "eval_mode": mode_name,
                    "avg_error": round(avg_err, 6),
                    "accuracy_pct": round(accuracy, 2),
                    "samples": len(errors),
                }
            )
        results.sort(key=lambda x: x["accuracy_pct"], reverse=True)
        return results

    def calibrate_proxy_metrics(self) -> list[dict[str, Any]]:
        """Calibrate proxy metric correlation with true eval score."""
        pairs = [
            (r.proxy_score, r.eval_score)
            for r in self._records
            if r.eval_mode == EvalMode.PROXY_METRIC
        ]
        if len(pairs) < 2:
            return [{"calibrated": False, "reason": "insufficient_data"}]
        proxy_vals = [p[0] for p in pairs]
        true_vals = [p[1] for p in pairs]
        proxy_mean = sum(proxy_vals) / len(proxy_vals)
        true_mean = sum(true_vals) / len(true_vals)
        cov = sum(
            (proxy_vals[i] - proxy_mean) * (true_vals[i] - true_mean) for i in range(len(pairs))
        ) / len(pairs)
        proxy_var = sum((v - proxy_mean) ** 2 for v in proxy_vals) / len(proxy_vals)
        true_var = sum((v - true_mean) ** 2 for v in true_vals) / len(true_vals)
        denom = (proxy_var * true_var) ** 0.5
        correlation = round(cov / denom, 4) if denom > 0 else 0.0
        scale_factor = round(true_mean / proxy_mean, 4) if proxy_mean != 0 else 1.0
        bias = round(true_mean - proxy_mean * scale_factor, 6)
        return [
            {
                "correlation": correlation,
                "scale_factor": scale_factor,
                "bias": bias,
                "calibrated": abs(correlation) >= 0.8,
                "samples": len(pairs),
                "quality": "good" if abs(correlation) >= 0.8 else "poor",
            }
        ]
