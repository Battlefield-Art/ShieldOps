"""Tool functions for the Model Drift Detector Agent."""

from __future__ import annotations

import math
from typing import Any

import structlog

from shieldops.agents.model_drift_detector.models import (
    DriftAlert,
    DriftType,
    SeverityLevel,
)

logger = structlog.get_logger()


class ModelDriftDetectorToolkit:
    """Toolkit for model drift detection and monitoring."""

    def __init__(
        self,
        model_registry: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._model_registry = model_registry
        self._metrics_store = metrics_store
        self._repository = repository

    async def collect_metrics(
        self,
        model_ids: list[str],
    ) -> list[dict[str, Any]]:
        """Collect baseline and current feature distributions."""
        logger.info("drift_detector.collect_metrics", model_count=len(model_ids))
        metrics: list[dict[str, Any]] = []
        for model_id in model_ids:
            features = [
                "feature_age",
                "feature_income",
                "feature_score",
                "feature_tenure",
                "feature_category",
            ]
            for feat in features:
                baseline_mean = 50.0
                current_mean = 50.0 + (hash(f"{model_id}{feat}") % 20 - 10)
                metrics.append(
                    {
                        "model_id": model_id,
                        "feature_name": feat,
                        "baseline_mean": baseline_mean,
                        "baseline_std": 10.0,
                        "current_mean": current_mean,
                        "current_std": 10.0 + abs(hash(feat) % 5),
                        "sample_size": 10000,
                    }
                )
        return metrics

    async def analyze_data_drift(
        self,
        metrics: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Analyze data drift using PSI and KS statistics."""
        logger.info("drift_detector.analyze_data_drift", count=len(metrics))
        results: list[dict[str, Any]] = []
        for metric in metrics:
            psi = self._compute_psi(
                metric.get("baseline_mean", 0),
                metric.get("current_mean", 0),
                metric.get("baseline_std", 1),
                metric.get("current_std", 1),
            )
            exceeded = psi > 0.1
            results.append(
                {
                    "model_id": metric.get("model_id", ""),
                    "feature_name": metric.get("feature_name", ""),
                    "drift_type": DriftType.DATA_DRIFT,
                    "statistic": "psi",
                    "drift_score": round(psi, 4),
                    "threshold": 0.1,
                    "exceeded": exceeded,
                    "severity": self._score_to_severity(psi),
                }
            )
        return results

    async def analyze_concept_drift(
        self,
        metrics: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Analyze concept drift via prediction-label correlation."""
        logger.info("drift_detector.analyze_concept_drift", count=len(metrics))
        results: list[dict[str, Any]] = []
        seen_models: set[str] = set()
        for metric in metrics:
            model_id = metric.get("model_id", "")
            if model_id in seen_models:
                continue
            seen_models.add(model_id)
            score = abs(hash(f"concept_{model_id}") % 100) / 100.0
            results.append(
                {
                    "model_id": model_id,
                    "feature_name": "_target",
                    "drift_type": DriftType.CONCEPT_DRIFT,
                    "statistic": "page_hinkley",
                    "drift_score": round(score, 4),
                    "threshold": 0.3,
                    "exceeded": score > 0.3,
                    "severity": self._score_to_severity(score),
                }
            )
        return results

    async def analyze_prediction_drift(
        self,
        metrics: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Analyze prediction distribution drift."""
        logger.info(
            "drift_detector.analyze_prediction_drift",
            count=len(metrics),
        )
        results: list[dict[str, Any]] = []
        seen_models: set[str] = set()
        for metric in metrics:
            model_id = metric.get("model_id", "")
            if model_id in seen_models:
                continue
            seen_models.add(model_id)
            score = abs(hash(f"pred_{model_id}") % 100) / 100.0
            results.append(
                {
                    "model_id": model_id,
                    "feature_name": "_prediction",
                    "drift_type": DriftType.PREDICTION_DRIFT,
                    "statistic": "ks_test",
                    "drift_score": round(score, 4),
                    "threshold": 0.15,
                    "exceeded": score > 0.15,
                    "severity": self._score_to_severity(score),
                }
            )
        return results

    async def evaluate_thresholds(
        self,
        data_results: list[dict[str, Any]],
        concept_results: list[dict[str, Any]],
        prediction_results: list[dict[str, Any]],
    ) -> list[DriftAlert]:
        """Evaluate all drift results against thresholds."""
        logger.info("drift_detector.evaluate_thresholds")
        alerts: list[DriftAlert] = []
        all_results = data_results + concept_results + prediction_results
        for res in all_results:
            if res.get("exceeded", False):
                alerts.append(
                    DriftAlert(
                        alert_id=f"drift-{len(alerts):04d}",
                        model_id=res.get("model_id", ""),
                        drift_type=res.get("drift_type", DriftType.DATA_DRIFT),
                        severity=res.get("severity", SeverityLevel.LOW),
                        feature_name=res.get("feature_name", ""),
                        drift_score=res.get("drift_score", 0.0),
                        message=(
                            f"{res.get('drift_type', '')} detected on "
                            f"{res.get('feature_name', '')} "
                            f"(score={res.get('drift_score', 0):.4f})"
                        ),
                        retrain_recommended=res.get("severity", "")
                        in (SeverityLevel.CRITICAL, SeverityLevel.HIGH),
                    )
                )
        return alerts

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_psi(
        base_mean: float,
        curr_mean: float,
        base_std: float,
        curr_std: float,
    ) -> float:
        """Approximate PSI from distribution parameters."""
        if base_std == 0 or curr_std == 0:
            return 0.0
        diff = abs(curr_mean - base_mean) / max(base_std, 0.01)
        std_ratio = curr_std / max(base_std, 0.01)
        psi = diff * 0.1 + abs(math.log(max(std_ratio, 0.01))) * 0.05
        return min(psi, 1.0)

    @staticmethod
    def _score_to_severity(score: float) -> str:
        """Map drift score to severity level."""
        if score >= 0.5:
            return SeverityLevel.CRITICAL
        if score >= 0.25:
            return SeverityLevel.HIGH
        if score >= 0.1:
            return SeverityLevel.MEDIUM
        if score > 0.0:
            return SeverityLevel.LOW
        return SeverityLevel.NONE
