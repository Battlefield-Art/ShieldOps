"""Incident Prediction Model Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    ConfidenceAssessment,
    EarlyWarning,
    FeatureVector,
    IndicatorCategory,
    LeadingIndicator,
    PredictionResult,
    RiskLevel,
)

logger = structlog.get_logger()

_SAMPLE_INDICATORS: list[dict[str, Any]] = [
    {
        "name": "failed_login_rate",
        "category": "behavioral",
        "value": 45.0,
        "baseline": 12.0,
        "source": "auth_logs",
    },
    {
        "name": "outbound_data_volume",
        "category": "volumetric",
        "value": 850.0,
        "baseline": 200.0,
        "source": "network_monitor",
    },
    {
        "name": "alert_frequency",
        "category": "anomaly",
        "value": 28.0,
        "baseline": 8.0,
        "source": "siem",
    },
    {
        "name": "privilege_escalation_attempts",
        "category": "behavioral",
        "value": 7.0,
        "baseline": 1.0,
        "source": "edr",
    },
    {
        "name": "dns_query_entropy",
        "category": "signature",
        "value": 4.2,
        "baseline": 2.8,
        "source": "dns_monitor",
    },
    {
        "name": "weekend_access_spike",
        "category": "temporal",
        "value": 34.0,
        "baseline": 5.0,
        "source": "access_logs",
    },
    {
        "name": "cpu_utilization_anomaly",
        "category": "environmental",
        "value": 92.0,
        "baseline": 55.0,
        "source": "infra_monitor",
    },
    {
        "name": "new_process_creation",
        "category": "anomaly",
        "value": 156.0,
        "baseline": 40.0,
        "source": "endpoint_agent",
    },
]

_INCIDENT_TYPES = [
    "data_breach",
    "ransomware",
    "insider_threat",
    "ddos_attack",
    "credential_compromise",
    "lateral_movement",
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class IncidentPredictionModelToolkit:
    """Tools for incident prediction modeling."""

    def __init__(
        self,
        telemetry_source: Any | None = None,
        model_service: Any | None = None,
    ) -> None:
        self._telemetry_source = telemetry_source
        self._model_service = model_service

    async def collect_indicators(
        self,
        tenant_id: str,
    ) -> list[LeadingIndicator]:
        """Collect leading indicators from telemetry."""
        logger.info(
            "ipm.collect_indicators",
            tenant_id=tenant_id,
        )

        if self._telemetry_source is not None:
            try:
                raw = await self._telemetry_source.get_indicators(
                    tenant_id=tenant_id,
                )
                return [LeadingIndicator(**r) for r in raw]
            except Exception:
                logger.exception("ipm.collect_indicators.error")

        indicators: list[LeadingIndicator] = []
        for i, ind in enumerate(_SAMPLE_INDICATORS):
            noise = random.uniform(-5.0, 5.0)  # noqa: S311
            val = ind["value"] + noise
            base = ind["baseline"]
            deviation = round((val - base) / base * 100, 1) if base else 0.0
            indicators.append(
                LeadingIndicator(
                    id=_gen_id("IND", tenant_id, i),
                    name=ind["name"],
                    category=IndicatorCategory(ind["category"]),
                    value=round(val, 1),
                    baseline_value=base,
                    deviation=deviation,
                    source=ind["source"],
                    timestamp="2026-03-30T12:00:00Z",
                )
            )
        return indicators

    async def extract_features(
        self,
        indicators: list[LeadingIndicator],
    ) -> list[FeatureVector]:
        """Extract feature vectors from indicators."""
        logger.info(
            "ipm.extract_features",
            count=len(indicators),
        )

        vectors: list[FeatureVector] = []
        for i, ind in enumerate(indicators):
            importance = random.uniform(0.3, 1.0)  # noqa: S311
            vectors.append(
                FeatureVector(
                    id=_gen_id("FV", ind.id, i),
                    indicator_id=ind.id,
                    features={
                        "value_norm": round(ind.value / max(ind.baseline_value, 1), 3),
                        "deviation_pct": round(ind.deviation, 1),
                        "z_score": round(
                            (ind.value - ind.baseline_value) / max(ind.baseline_value * 0.2, 1),
                            2,
                        ),
                    },
                    normalized=True,
                    importance_score=round(importance, 2),
                )
            )
        return vectors

    async def run_prediction_model(
        self,
        feature_vectors: list[FeatureVector],
    ) -> list[PredictionResult]:
        """Run the prediction model on feature vectors."""
        logger.info(
            "ipm.run_prediction_model",
            count=len(feature_vectors),
        )

        if self._model_service is not None:
            try:
                raw = await self._model_service.predict(
                    features=[fv.features for fv in feature_vectors],
                )
                return [PredictionResult(**r) for r in raw]
            except Exception:
                logger.exception("ipm.run_prediction_model.error")

        predictions: list[PredictionResult] = []
        for i, inc_type in enumerate(_INCIDENT_TYPES):
            prob = random.uniform(0.1, 0.95)  # noqa: S311
            if prob > 0.8:
                risk = RiskLevel.CRITICAL
            elif prob > 0.6:
                risk = RiskLevel.HIGH
            elif prob > 0.4:
                risk = RiskLevel.MEDIUM
            else:
                risk = RiskLevel.LOW
            hours = random.choice([4, 8, 12, 24, 48, 72])  # noqa: S311
            contributing = [fv.indicator_id for fv in feature_vectors if fv.importance_score > 0.6][
                :3
            ]
            predictions.append(
                PredictionResult(
                    id=_gen_id("PR", inc_type, i),
                    incident_type=inc_type,
                    probability=round(prob, 3),
                    risk_level=risk,
                    time_horizon_hours=hours,
                    contributing_indicators=contributing,
                    model_version="v1.2",
                )
            )
        return predictions

    async def assess_confidence(
        self,
        predictions: list[PredictionResult],
        feature_vectors: list[FeatureVector],
    ) -> list[ConfidenceAssessment]:
        """Assess confidence of predictions."""
        logger.info(
            "ipm.assess_confidence",
            count=len(predictions),
        )

        assessments: list[ConfidenceAssessment] = []
        for i, p in enumerate(predictions):
            model_conf = random.uniform(0.5, 0.95)  # noqa: S311
            data_quality = random.uniform(0.6, 0.98)  # noqa: S311
            hist_acc = random.uniform(0.65, 0.92)  # noqa: S311
            overall = round(
                (model_conf * 0.4 + data_quality * 0.3 + hist_acc * 0.3),
                3,
            )
            caveats: list[str] = []
            if data_quality < 0.7:
                caveats.append("Limited data quality for this indicator set")
            if hist_acc < 0.75:
                caveats.append("Historical accuracy below threshold")
            assessments.append(
                ConfidenceAssessment(
                    id=_gen_id("CA", p.id, i),
                    prediction_id=p.id,
                    model_confidence=round(model_conf, 3),
                    data_quality_score=round(data_quality, 3),
                    historical_accuracy=round(hist_acc, 3),
                    overall_confidence=overall,
                    caveats=caveats,
                )
            )
        return assessments

    async def generate_warnings(
        self,
        predictions: list[PredictionResult],
        assessments: list[ConfidenceAssessment],
    ) -> list[EarlyWarning]:
        """Generate early warnings from predictions."""
        logger.info(
            "ipm.generate_warnings",
            count=len(predictions),
        )

        assess_map = {a.prediction_id: a for a in assessments}
        warnings: list[EarlyWarning] = []
        idx = 0
        for p in predictions:
            if p.probability < 0.4:
                continue
            ca = assess_map.get(p.id)
            conf_label = f" (conf: {ca.overall_confidence:.0%})" if ca else ""
            sev = (
                "critical"
                if p.risk_level == RiskLevel.CRITICAL
                else ("high" if p.risk_level == RiskLevel.HIGH else "medium")
            )
            warnings.append(
                EarlyWarning(
                    id=_gen_id("EW", p.id, idx),
                    prediction_id=p.id,
                    severity=sev,
                    title=(f"Predicted {p.incident_type} within {p.time_horizon_hours}h"),
                    description=(f"Probability {p.probability:.0%}{conf_label}"),
                    recommended_actions=[
                        f"Review {p.incident_type} defenses",
                        "Verify monitoring coverage",
                        "Pre-stage response resources",
                    ],
                    expires_at="2026-03-31T12:00:00Z",
                )
            )
            idx += 1
        return warnings

    async def record_metric(
        self,
        metric_name: str,
        value: float,
    ) -> dict[str, Any]:
        """Record a prediction metric."""
        logger.info(
            "ipm.record_metric",
            metric=metric_name,
            value=value,
        )
        return {
            "metric": metric_name,
            "value": value,
            "recorded": True,
        }
