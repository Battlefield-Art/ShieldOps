"""Span to Metric Conversion Engine —
evaluate conversion accuracy, detect cardinality explosion,
optimize conversion rules."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ConversionType(StrEnum):
    REQUEST_RATE = "request_rate"
    ERROR_RATE = "error_rate"
    DURATION_HISTOGRAM = "duration_histogram"
    CUSTOM_AGGREGATE = "custom_aggregate"


class CardinalityRisk(StrEnum):
    SAFE = "safe"
    ELEVATED = "elevated"
    HIGH = "high"
    EXPLOSIVE = "explosive"


class MetricGranularity(StrEnum):
    SERVICE_LEVEL = "service_level"
    ENDPOINT_LEVEL = "endpoint_level"
    OPERATION_LEVEL = "operation_level"
    ATTRIBUTE_LEVEL = "attribute_level"


# --- Models ---


class SpanToMetricRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str = ""
    conversion_type: ConversionType = ConversionType.REQUEST_RATE
    cardinality_risk: CardinalityRisk = CardinalityRisk.SAFE
    metric_granularity: MetricGranularity = MetricGranularity.SERVICE_LEVEL
    spans_per_sec: float = 0.0
    metrics_produced: int = 0
    unique_label_sets: int = 0
    accuracy_pct: float = 100.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SpanToMetricAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str = ""
    conversion_type: ConversionType = ConversionType.REQUEST_RATE
    cardinality_risk: CardinalityRisk = CardinalityRisk.SAFE
    conversion_ratio: float = 0.0
    explosion_detected: bool = False
    accuracy_score: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SpanToMetricReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_accuracy_pct: float = 0.0
    by_conversion_type: dict[str, int] = Field(default_factory=dict)
    by_cardinality_risk: dict[str, int] = Field(default_factory=dict)
    by_metric_granularity: dict[str, int] = Field(default_factory=dict)
    explosive_rules: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class SpanToMetricConversionEngine:
    """Evaluate conversion accuracy, detect cardinality explosion,
    optimize conversion rules."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[SpanToMetricRecord] = []
        self._analyses: dict[str, SpanToMetricAnalysis] = {}
        logger.info("span_to_metric_conversion_engine.init", max_records=max_records)

    def add_record(
        self,
        rule_id: str = "",
        conversion_type: ConversionType = ConversionType.REQUEST_RATE,
        cardinality_risk: CardinalityRisk = CardinalityRisk.SAFE,
        metric_granularity: MetricGranularity = MetricGranularity.SERVICE_LEVEL,
        spans_per_sec: float = 0.0,
        metrics_produced: int = 0,
        unique_label_sets: int = 0,
        accuracy_pct: float = 100.0,
        description: str = "",
    ) -> SpanToMetricRecord:
        record = SpanToMetricRecord(
            rule_id=rule_id,
            conversion_type=conversion_type,
            cardinality_risk=cardinality_risk,
            metric_granularity=metric_granularity,
            spans_per_sec=spans_per_sec,
            metrics_produced=metrics_produced,
            unique_label_sets=unique_label_sets,
            accuracy_pct=accuracy_pct,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "span_to_metric.record_added",
            record_id=record.id,
            rule_id=rule_id,
        )
        return record

    def process(self, key: str) -> SpanToMetricAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        conversion_ratio = round(
            (rec.metrics_produced / rec.spans_per_sec) if rec.spans_per_sec > 0 else 0.0,
            4,
        )
        explosion_detected = (
            rec.cardinality_risk
            in (
                CardinalityRisk.HIGH,
                CardinalityRisk.EXPLOSIVE,
            )
            or rec.unique_label_sets > 50000
        )
        accuracy_score = round(
            rec.accuracy_pct * (1.0 - min(rec.unique_label_sets / 100000.0, 0.5)), 2
        )
        analysis = SpanToMetricAnalysis(
            rule_id=rec.rule_id,
            conversion_type=rec.conversion_type,
            cardinality_risk=rec.cardinality_risk,
            conversion_ratio=conversion_ratio,
            explosion_detected=explosion_detected,
            accuracy_score=accuracy_score,
            description=(f"Rule {rec.rule_id} conversion ratio {conversion_ratio:.4f}"),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> SpanToMetricReport:
        by_type: dict[str, int] = {}
        by_cardinality: dict[str, int] = {}
        by_granularity: dict[str, int] = {}
        acc_vals: list[float] = []
        explosive_rules: list[str] = []
        for r in self._records:
            kt = r.conversion_type.value
            by_type[kt] = by_type.get(kt, 0) + 1
            kc = r.cardinality_risk.value
            by_cardinality[kc] = by_cardinality.get(kc, 0) + 1
            kg = r.metric_granularity.value
            by_granularity[kg] = by_granularity.get(kg, 0) + 1
            acc_vals.append(r.accuracy_pct)
            if r.cardinality_risk == CardinalityRisk.EXPLOSIVE and r.rule_id not in explosive_rules:
                explosive_rules.append(r.rule_id)
        avg_acc = round(sum(acc_vals) / len(acc_vals), 2) if acc_vals else 0.0
        recs: list[str] = []
        if explosive_rules:
            recs.append(
                f"{len(explosive_rules)} rules with explosive cardinality — add label filters"
            )
        high_card = by_cardinality.get("high", 0)
        if high_card > 0:
            recs.append(f"{high_card} high-cardinality rules — review attribute dimensions")
        if not recs:
            recs.append("Span-to-metric conversion rules are healthy")
        return SpanToMetricReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_accuracy_pct=avg_acc,
            by_conversion_type=by_type,
            by_cardinality_risk=by_cardinality,
            by_metric_granularity=by_granularity,
            explosive_rules=explosive_rules[:10],
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        cardinality_dist: dict[str, int] = {}
        for r in self._records:
            k = r.cardinality_risk.value
            cardinality_dist[k] = cardinality_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "cardinality_distribution": cardinality_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("span_to_metric_conversion_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def evaluate_conversion_accuracy(self) -> list[dict[str, Any]]:
        """Evaluate accuracy per conversion rule."""
        rule_data: dict[str, list[SpanToMetricRecord]] = {}
        for r in self._records:
            rule_data.setdefault(r.rule_id, []).append(r)
        results: list[dict[str, Any]] = []
        for rid, recs in rule_data.items():
            avg_acc = sum(r.accuracy_pct for r in recs) / len(recs)
            min_acc = min(r.accuracy_pct for r in recs)
            results.append(
                {
                    "rule_id": rid,
                    "avg_accuracy_pct": round(avg_acc, 2),
                    "min_accuracy_pct": round(min_acc, 2),
                    "conversion_type": recs[-1].conversion_type.value,
                    "samples": len(recs),
                }
            )
        results.sort(key=lambda x: x["avg_accuracy_pct"])
        return results

    def detect_cardinality_explosion(self) -> list[dict[str, Any]]:
        """Detect rules with explosive or high cardinality."""
        rule_data: dict[str, list[SpanToMetricRecord]] = {}
        for r in self._records:
            rule_data.setdefault(r.rule_id, []).append(r)
        results: list[dict[str, Any]] = []
        for rid, recs in rule_data.items():
            max_labels = max(r.unique_label_sets for r in recs)
            explosive_samples = sum(
                1 for r in recs if r.cardinality_risk == CardinalityRisk.EXPLOSIVE
            )
            if max_labels > 10000 or explosive_samples > 0:
                results.append(
                    {
                        "rule_id": rid,
                        "max_unique_label_sets": max_labels,
                        "explosive_samples": explosive_samples,
                        "granularity": recs[-1].metric_granularity.value,
                        "risk_level": "explosive" if explosive_samples > 0 else "high",
                    }
                )
        results.sort(key=lambda x: x["max_unique_label_sets"], reverse=True)
        return results

    def optimize_conversion_rules(self) -> list[dict[str, Any]]:
        """Recommend optimizations for conversion rules."""
        rule_data: dict[str, list[SpanToMetricRecord]] = {}
        for r in self._records:
            rule_data.setdefault(r.rule_id, []).append(r)
        results: list[dict[str, Any]] = []
        for rid, recs in rule_data.items():
            avg_acc = sum(r.accuracy_pct for r in recs) / len(recs)
            avg_labels = sum(r.unique_label_sets for r in recs) / len(recs)
            suggestions: list[str] = []
            if avg_labels > 10000:
                suggestions.append("reduce label dimensions with attribute filter")
            if avg_acc < 90.0:
                suggestions.append("review aggregation function for accuracy loss")
            if recs[-1].metric_granularity == MetricGranularity.ATTRIBUTE_LEVEL:
                suggestions.append("consider promoting to operation-level granularity")
            if suggestions:
                results.append(
                    {
                        "rule_id": rid,
                        "avg_accuracy_pct": round(avg_acc, 2),
                        "avg_unique_label_sets": round(avg_labels, 0),
                        "suggestions": suggestions,
                        "priority": "high" if avg_labels > 50000 else "medium",
                    }
                )
        results.sort(key=lambda x: len(x["suggestions"]), reverse=True)
        return results
