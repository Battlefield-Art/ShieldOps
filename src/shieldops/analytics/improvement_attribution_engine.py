"""Improvement Attribution Engine —
attribute improvements to changes, detect confounded
experiments, and build improvement knowledge base."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ChangeType(StrEnum):
    PARAMETER_CHANGE = "parameter_change"
    DATA_CHANGE = "data_change"
    ARCHITECTURE_CHANGE = "architecture_change"
    PROMPT_CHANGE = "prompt_change"


class AttributionConfidence(StrEnum):
    CAUSAL = "causal"
    CORRELATIONAL = "correlational"
    SUGGESTIVE = "suggestive"
    UNCERTAIN = "uncertain"


class ImprovementMagnitude(StrEnum):
    BREAKTHROUGH = "breakthrough"
    SIGNIFICANT = "significant"
    MARGINAL = "marginal"
    NEGLIGIBLE = "negligible"


# --- Models ---


class ImprovementAttributionRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    experiment_id: str = ""
    change_id: str = ""
    change_type: ChangeType = ChangeType.PARAMETER_CHANGE
    attribution_confidence: AttributionConfidence = AttributionConfidence.CORRELATIONAL
    magnitude: ImprovementMagnitude = ImprovementMagnitude.MARGINAL
    improvement_delta: float = 0.0
    confounded: bool = False
    simultaneous_changes: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ImprovementAttributionAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    experiment_id: str = ""
    primary_driver: str = ""
    attribution_confidence: AttributionConfidence = AttributionConfidence.CORRELATIONAL
    total_improvement: float = 0.0
    confounded: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ImprovementAttributionReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    by_change_type: dict[str, int] = Field(default_factory=dict)
    by_attribution_confidence: dict[str, int] = Field(default_factory=dict)
    by_magnitude: dict[str, int] = Field(default_factory=dict)
    top_change_types: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ImprovementAttributionEngine:
    """Attribute improvements to changes, detect confounded experiments,
    and build an improvement knowledge base."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[ImprovementAttributionRecord] = []
        self._analyses: dict[str, ImprovementAttributionAnalysis] = {}
        logger.info(
            "improvement_attribution.init",
            max_records=max_records,
        )

    def add_record(
        self,
        experiment_id: str = "",
        change_id: str = "",
        change_type: ChangeType = ChangeType.PARAMETER_CHANGE,
        attribution_confidence: AttributionConfidence = AttributionConfidence.CORRELATIONAL,
        magnitude: ImprovementMagnitude = ImprovementMagnitude.MARGINAL,
        improvement_delta: float = 0.0,
        confounded: bool = False,
        simultaneous_changes: int = 0,
        description: str = "",
    ) -> ImprovementAttributionRecord:
        record = ImprovementAttributionRecord(
            experiment_id=experiment_id,
            change_id=change_id,
            change_type=change_type,
            attribution_confidence=attribution_confidence,
            magnitude=magnitude,
            improvement_delta=improvement_delta,
            confounded=confounded,
            simultaneous_changes=simultaneous_changes,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "improvement_attribution.record_added",
            record_id=record.id,
            experiment_id=experiment_id,
        )
        return record

    def process(self, key: str) -> ImprovementAttributionAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        exp_recs = [r for r in self._records if r.experiment_id == rec.experiment_id]
        total_imp = sum(r.improvement_delta for r in exp_recs)
        change_deltas: dict[str, float] = {}
        for r in exp_recs:
            change_deltas[r.change_type.value] = (
                change_deltas.get(r.change_type.value, 0.0) + r.improvement_delta
            )
        primary_driver = max(change_deltas, key=lambda x: change_deltas[x]) if change_deltas else ""
        confounded = any(r.confounded for r in exp_recs)
        analysis = ImprovementAttributionAnalysis(
            experiment_id=rec.experiment_id,
            primary_driver=primary_driver,
            attribution_confidence=rec.attribution_confidence,
            total_improvement=round(total_imp, 6),
            confounded=confounded,
            description=f"Experiment {rec.experiment_id} driver={primary_driver}",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> ImprovementAttributionReport:
        by_ct: dict[str, int] = {}
        by_ac: dict[str, int] = {}
        by_m: dict[str, int] = {}
        change_type_deltas: dict[str, float] = {}
        for r in self._records:
            by_ct[r.change_type.value] = by_ct.get(r.change_type.value, 0) + 1
            by_ac[r.attribution_confidence.value] = by_ac.get(r.attribution_confidence.value, 0) + 1
            by_m[r.magnitude.value] = by_m.get(r.magnitude.value, 0) + 1
            change_type_deltas[r.change_type.value] = (
                change_type_deltas.get(r.change_type.value, 0.0) + r.improvement_delta
            )
        top_change_types = sorted(
            change_type_deltas, key=lambda x: change_type_deltas[x], reverse=True
        )[:10]
        recs_list: list[str] = []
        uncertain = by_ac.get("uncertain", 0)
        if uncertain > 0:
            recs_list.append(f"{uncertain} uncertain attributions — isolate changes")
        confounded_count = sum(1 for r in self._records if r.confounded)
        if confounded_count > 0:
            recs_list.append(f"{confounded_count} confounded experiments detected")
        if not recs_list:
            recs_list.append("Attribution quality is high")
        return ImprovementAttributionReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            by_change_type=by_ct,
            by_attribution_confidence=by_ac,
            by_magnitude=by_m,
            top_change_types=top_change_types,
            recommendations=recs_list,
        )

    def get_stats(self) -> dict[str, Any]:
        ct_dist: dict[str, int] = {}
        for r in self._records:
            ct_dist[r.change_type.value] = ct_dist.get(r.change_type.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "change_type_distribution": ct_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("improvement_attribution.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def attribute_improvement_to_changes(self, experiment_id: str) -> list[dict[str, Any]]:
        """Attribute improvement delta to each change type for an experiment."""
        exp_recs = [r for r in self._records if r.experiment_id == experiment_id]
        if not exp_recs:
            return []
        attribution: dict[str, dict[str, Any]] = {}
        for r in exp_recs:
            ct = r.change_type.value
            if ct not in attribution:
                attribution[ct] = {"total_delta": 0.0, "count": 0, "avg_confidence": 0.0}
            attribution[ct]["total_delta"] += r.improvement_delta
            attribution[ct]["count"] += 1
            conf_map = {
                AttributionConfidence.CAUSAL: 1.0,
                AttributionConfidence.CORRELATIONAL: 0.75,
                AttributionConfidence.SUGGESTIVE: 0.5,
                AttributionConfidence.UNCERTAIN: 0.25,
            }
            attribution[ct]["avg_confidence"] += conf_map.get(r.attribution_confidence, 0.5)
        results: list[dict[str, Any]] = []
        for ct, data in attribution.items():
            cnt = data["count"]
            avg_conf = data["avg_confidence"] / cnt if cnt > 0 else 0.0
            results.append(
                {
                    "change_type": ct,
                    "total_improvement": round(data["total_delta"], 6),
                    "count": cnt,
                    "avg_confidence": round(avg_conf, 4),
                    "effective_contribution": round(data["total_delta"] * avg_conf, 6),
                }
            )
        results.sort(key=lambda x: x["effective_contribution"], reverse=True)
        return results

    def detect_confounded_experiments(self) -> list[dict[str, Any]]:
        """Detect experiments with confounded attribution."""
        exp_data: dict[str, dict[str, Any]] = {}
        for r in self._records:
            eid = r.experiment_id
            if eid not in exp_data:
                exp_data[eid] = {"confounded_count": 0, "total": 0, "max_simultaneous": 0}
            exp_data[eid]["total"] += 1
            if r.confounded:
                exp_data[eid]["confounded_count"] += 1
            exp_data[eid]["max_simultaneous"] = max(
                exp_data[eid]["max_simultaneous"], r.simultaneous_changes
            )
        results: list[dict[str, Any]] = []
        for eid, data in exp_data.items():
            conf_ratio = data["confounded_count"] / data["total"] if data["total"] > 0 else 0.0
            is_problematic = conf_ratio > 0.3 or data["max_simultaneous"] > 2
            results.append(
                {
                    "experiment_id": eid,
                    "confounded_ratio": round(conf_ratio, 4),
                    "max_simultaneous_changes": data["max_simultaneous"],
                    "is_problematic": is_problematic,
                    "total_records": data["total"],
                }
            )
        results.sort(key=lambda x: x["confounded_ratio"], reverse=True)
        return results

    def build_improvement_knowledge_base(self) -> dict[str, Any]:
        """Aggregate improvement patterns into a knowledge base."""
        change_type_stats: dict[str, dict[str, Any]] = {}
        for r in self._records:
            ct = r.change_type.value
            if ct not in change_type_stats:
                change_type_stats[ct] = {
                    "total_delta": 0.0,
                    "count": 0,
                    "breakthroughs": 0,
                    "regressions": 0,
                }
            change_type_stats[ct]["total_delta"] += r.improvement_delta
            change_type_stats[ct]["count"] += 1
            if r.magnitude == ImprovementMagnitude.BREAKTHROUGH:
                change_type_stats[ct]["breakthroughs"] += 1
            if r.improvement_delta < 0:
                change_type_stats[ct]["regressions"] += 1
        kb: list[dict[str, Any]] = []
        for ct, data in change_type_stats.items():
            cnt = data["count"]
            avg_delta = data["total_delta"] / cnt if cnt > 0 else 0.0
            success_rate = 1.0 - (data["regressions"] / cnt) if cnt > 0 else 0.0
            kb.append(
                {
                    "change_type": ct,
                    "avg_improvement": round(avg_delta, 6),
                    "success_rate": round(success_rate, 4),
                    "breakthrough_count": data["breakthroughs"],
                    "total_experiments": cnt,
                    "recommended": avg_delta > 0 and success_rate >= 0.6,
                }
            )
        kb.sort(key=lambda x: x["avg_improvement"], reverse=True)
        return {
            "knowledge_entries": kb,
            "total_change_types": len(kb),
            "generated_at": time.time(),
        }
