"""ModelBackdoorDetector — detects backdoor attacks and poisoning in AI models."""

from __future__ import annotations

import math
import time
import uuid
from collections import Counter
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class BackdoorType(StrEnum):
    DATA_POISONING = "data_poisoning"
    MODEL_POISONING = "model_poisoning"
    TROJAN_TRIGGER = "trojan_trigger"
    WEIGHT_MANIPULATION = "weight_manipulation"


class DetectionMethod(StrEnum):
    STATISTICAL = "statistical"
    BEHAVIORAL = "behavioral"
    SPECTRAL = "spectral"
    ACTIVATION_ANALYSIS = "activation_analysis"


class SeverityRating(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# --- Models ---


class BackdoorRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    model_id: str = ""
    model_name: str = ""
    detection_method: DetectionMethod = DetectionMethod.STATISTICAL
    backdoor_type: BackdoorType = BackdoorType.DATA_POISONING
    severity: SeverityRating = SeverityRating.LOW
    confidence: float = 0.0
    anomaly_score: float = 0.0
    affected_layers: list[str] = Field(default_factory=list)
    trigger_pattern: str = ""
    baseline_accuracy: float = 0.0
    poisoned_accuracy: float = 0.0
    clean_accuracy_drop: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: float = Field(default_factory=time.time)


class BackdoorAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    model_id: str = ""
    total_scans: int = 0
    detections_by_type: dict[str, int] = Field(default_factory=dict)
    detections_by_method: dict[str, int] = Field(default_factory=dict)
    max_severity: SeverityRating = SeverityRating.LOW
    avg_confidence: float = 0.0
    avg_anomaly_score: float = 0.0
    affected_layer_count: int = 0
    is_compromised: bool = False
    recommendations: list[str] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)


class BackdoorReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    unique_models: int = 0
    compromised_models: int = 0
    severity_breakdown: dict[str, int] = Field(default_factory=dict)
    type_breakdown: dict[str, int] = Field(default_factory=dict)
    method_breakdown: dict[str, int] = Field(default_factory=dict)
    high_risk_models: list[dict[str, Any]] = Field(default_factory=list)
    integrity_summary: dict[str, Any] = Field(default_factory=dict)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


_SEVERITY_ORDER = [
    SeverityRating.LOW,
    SeverityRating.MEDIUM,
    SeverityRating.HIGH,
    SeverityRating.CRITICAL,
]
_COMPROMISED_THRESHOLD = 0.7


class ModelBackdoorDetector:
    """Detects backdoor attacks and poisoning in AI models."""

    def __init__(self, max_records: int = 10000) -> None:
        self._records: list[BackdoorRecord] = []
        self._max = max_records
        logger.info("model_backdoor_detector.initialized", max_records=max_records)

    # -- core methods --

    def add_record(self, **kwargs: Any) -> BackdoorRecord:
        """Add a backdoor detection scan record."""
        rec = BackdoorRecord(**kwargs)
        # Auto-classify severity from confidence and anomaly score
        if rec.severity == SeverityRating.LOW and rec.confidence > 0:
            combined = (rec.confidence + rec.anomaly_score) / 2
            if combined >= 0.9:
                rec.severity = SeverityRating.CRITICAL
            elif combined >= 0.7:
                rec.severity = SeverityRating.HIGH
            elif combined >= 0.4:
                rec.severity = SeverityRating.MEDIUM
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.debug(
            "model_backdoor_detector.record_added",
            model_id=rec.model_id,
            backdoor_type=rec.backdoor_type,
            severity=rec.severity,
        )
        return rec

    def process(self, model_id: str) -> BackdoorAnalysis:
        """Analyze backdoor detections for a specific model."""
        filtered = [r for r in self._records if r.model_id == model_id]
        if not filtered:
            return BackdoorAnalysis(model_id=model_id)

        type_dist: Counter[str] = Counter()
        method_dist: Counter[str] = Counter()
        max_sev_idx = 0
        total_conf = 0.0
        total_anomaly = 0.0
        all_layers: set[str] = set()

        for r in filtered:
            type_dist[r.backdoor_type.value] += 1
            method_dist[r.detection_method.value] += 1
            sev_idx = _SEVERITY_ORDER.index(r.severity) if r.severity in _SEVERITY_ORDER else 0
            max_sev_idx = max(max_sev_idx, sev_idx)
            total_conf += r.confidence
            total_anomaly += r.anomaly_score
            all_layers.update(r.affected_layers)

        avg_conf = round(total_conf / len(filtered), 3)
        avg_anomaly = round(total_anomaly / len(filtered), 3)
        is_compromised = avg_conf >= _COMPROMISED_THRESHOLD or max_sev_idx >= 3

        recommendations: list[str] = []
        if is_compromised:
            recommendations.append(
                f"Model {model_id} likely compromised — quarantine and retrain from clean data"
            )
        if type_dist.get(BackdoorType.TROJAN_TRIGGER, 0) > 0:
            recommendations.append("Trojan trigger detected — run Neural Cleanse or STRIP defense")
        if type_dist.get(BackdoorType.DATA_POISONING, 0) > 0:
            recommendations.append("Data poisoning detected — audit training data pipeline")
        if avg_anomaly > 0.5:
            recommendations.append(
                f"High anomaly score ({avg_anomaly}) — run spectral signature analysis"
            )

        return BackdoorAnalysis(
            model_id=model_id,
            total_scans=len(filtered),
            detections_by_type=dict(type_dist),
            detections_by_method=dict(method_dist),
            max_severity=_SEVERITY_ORDER[max_sev_idx],
            avg_confidence=avg_conf,
            avg_anomaly_score=avg_anomaly,
            affected_layer_count=len(all_layers),
            is_compromised=is_compromised,
            recommendations=recommendations,
        )

    def generate_report(self) -> BackdoorReport:
        """Generate a comprehensive backdoor detection report."""
        if not self._records:
            return BackdoorReport()

        sev_bk: Counter[str] = Counter()
        type_bk: Counter[str] = Counter()
        method_bk: Counter[str] = Counter()
        model_scores: dict[str, list[float]] = {}

        for r in self._records:
            sev_bk[r.severity.value] += 1
            type_bk[r.backdoor_type.value] += 1
            method_bk[r.detection_method.value] += 1
            model_scores.setdefault(r.model_id, []).append(r.confidence)

        # Identify compromised / high-risk models
        high_risk: list[dict[str, Any]] = []
        compromised_count = 0
        for mid, scores in model_scores.items():
            avg = sum(scores) / len(scores)
            if avg >= _COMPROMISED_THRESHOLD:
                compromised_count += 1
                high_risk.append(
                    {
                        "model_id": mid,
                        "avg_confidence": round(avg, 3),
                        "scan_count": len(scores),
                    }
                )

        total = len(self._records)
        integrity = self.assess_model_integrity()

        return BackdoorReport(
            total_records=total,
            unique_models=len(model_scores),
            compromised_models=compromised_count,
            severity_breakdown=dict(sev_bk),
            type_breakdown=dict(type_bk),
            method_breakdown=dict(method_bk),
            high_risk_models=sorted(high_risk, key=lambda x: x["avg_confidence"], reverse=True),
            integrity_summary=integrity,
        )

    def get_stats(self) -> dict[str, Any]:
        """Return summary statistics."""
        return {
            "total_records": len(self._records),
            "unique_models": len({r.model_id for r in self._records}),
            "critical_detections": sum(
                1 for r in self._records if r.severity == SeverityRating.CRITICAL
            ),
            "high_detections": sum(1 for r in self._records if r.severity == SeverityRating.HIGH),
        }

    def clear_data(self) -> None:
        """Clear all stored records."""
        self._records.clear()
        logger.info("model_backdoor_detector.cleared")

    # -- domain methods --

    def run_statistical_analysis(self, model_id: str) -> dict[str, Any]:
        """Run statistical analysis on model outputs to detect poisoning signals."""
        records = [r for r in self._records if r.model_id == model_id]
        if not records:
            return {"model_id": model_id, "result": "no_data", "indicators": []}

        anomaly_scores = [r.anomaly_score for r in records if r.anomaly_score > 0]
        if not anomaly_scores:
            return {"model_id": model_id, "result": "clean", "indicators": []}

        mean_score = sum(anomaly_scores) / len(anomaly_scores)
        variance = sum((s - mean_score) ** 2 for s in anomaly_scores) / len(anomaly_scores)
        stddev = math.sqrt(variance) if variance > 0 else 0.0

        # Detect outliers using z-score
        indicators: list[str] = []
        outlier_count = 0
        for s in anomaly_scores:
            if stddev > 0 and abs(s - mean_score) / stddev > 2.0:
                outlier_count += 1

        if outlier_count > len(anomaly_scores) * 0.1:
            indicators.append("high_outlier_rate")
        if mean_score > 0.6:
            indicators.append("elevated_mean_anomaly")
        if stddev > 0.3:
            indicators.append("high_score_variance")

        # Check accuracy drops
        acc_drops = [r.clean_accuracy_drop for r in records if r.clean_accuracy_drop > 0]
        if acc_drops:
            avg_drop = sum(acc_drops) / len(acc_drops)
            if avg_drop > 0.05:
                indicators.append(f"accuracy_degradation_{round(avg_drop * 100, 1)}pct")

        result = "suspicious" if indicators else "clean"
        return {
            "model_id": model_id,
            "result": result,
            "mean_anomaly": round(mean_score, 4),
            "stddev": round(stddev, 4),
            "outlier_count": outlier_count,
            "indicators": indicators,
            "sample_count": len(anomaly_scores),
        }

    def check_activation_patterns(self, model_id: str) -> dict[str, Any]:
        """Check for suspicious activation patterns that may indicate trojan triggers."""
        records = [
            r
            for r in self._records
            if r.model_id == model_id and r.detection_method == DetectionMethod.ACTIVATION_ANALYSIS
        ]
        if not records:
            return {"model_id": model_id, "suspicious_layers": [], "trojan_likelihood": 0.0}

        layer_counts: Counter[str] = Counter()
        trigger_patterns: list[str] = []
        for r in records:
            for layer in r.affected_layers:
                layer_counts[layer] += 1
            if r.trigger_pattern:
                trigger_patterns.append(r.trigger_pattern)

        # Layers appearing in multiple detections are suspicious
        suspicious = [layer for layer, count in layer_counts.items() if count >= 2]

        # Compute trojan likelihood based on repeat detections and confidence
        avg_conf = sum(r.confidence for r in records) / len(records) if records else 0.0
        repeat_factor = min(len(suspicious) / max(len(layer_counts), 1), 1.0)
        trojan_likelihood = round(avg_conf * 0.6 + repeat_factor * 0.4, 3)

        return {
            "model_id": model_id,
            "suspicious_layers": suspicious,
            "trigger_patterns_found": len(trigger_patterns),
            "unique_triggers": list(set(trigger_patterns)),
            "trojan_likelihood": trojan_likelihood,
            "scans_analyzed": len(records),
        }

    def assess_model_integrity(self) -> dict[str, Any]:
        """Assess overall model integrity across all tracked models."""
        if not self._records:
            return {"status": "no_data", "models_clean": 0, "models_at_risk": 0}

        model_groups: dict[str, list[BackdoorRecord]] = {}
        for r in self._records:
            model_groups.setdefault(r.model_id, []).append(r)

        clean = 0
        at_risk = 0
        compromised = 0

        for _mid, recs in model_groups.items():
            avg_conf = sum(r.confidence for r in recs) / len(recs)
            max_sev = max(
                (_SEVERITY_ORDER.index(r.severity) for r in recs if r.severity in _SEVERITY_ORDER),
                default=0,
            )
            if avg_conf >= _COMPROMISED_THRESHOLD or max_sev >= 3:
                compromised += 1
            elif avg_conf >= 0.4 or max_sev >= 2:
                at_risk += 1
            else:
                clean += 1

        total = len(model_groups)
        health_score = round(clean / total, 3) if total > 0 else 1.0

        return {
            "status": "healthy"
            if health_score >= 0.8
            else "degraded"
            if health_score >= 0.5
            else "critical",
            "health_score": health_score,
            "total_models": total,
            "models_clean": clean,
            "models_at_risk": at_risk,
            "models_compromised": compromised,
        }
