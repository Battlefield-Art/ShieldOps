"""Adaptive Security Agent — Tool functions for adaptive threshold management."""

from __future__ import annotations

import hashlib
import random
import time
from typing import Any

import structlog

from .models import (
    AdaptationResult,
    BaselineMetrics,
    ThreatContext,
    ThresholdProposal,
    ThresholdType,
)

logger = structlog.get_logger()

# Default baseline metrics per entity type
_DEFAULT_BASELINES: dict[str, list[dict[str, float]]] = {
    "host": [
        {"metric_name": "risk_score", "baseline_value": 0.35},
        {"metric_name": "alert_volume", "baseline_value": 12.0},
        {"metric_name": "anomaly_sensitivity", "baseline_value": 0.7},
        {"metric_name": "response_urgency", "baseline_value": 0.5},
    ],
    "user": [
        {"metric_name": "risk_score", "baseline_value": 0.25},
        {"metric_name": "alert_volume", "baseline_value": 8.0},
        {"metric_name": "anomaly_sensitivity", "baseline_value": 0.65},
        {"metric_name": "response_urgency", "baseline_value": 0.4},
    ],
    "ip": [
        {"metric_name": "risk_score", "baseline_value": 0.30},
        {"metric_name": "alert_volume", "baseline_value": 15.0},
        {"metric_name": "anomaly_sensitivity", "baseline_value": 0.75},
        {"metric_name": "response_urgency", "baseline_value": 0.45},
    ],
}

# Sigma threshold for drift detection
_DRIFT_SIGMA = 2.0
# Standard deviation fraction for mock drift
_MOCK_STD_FRACTION = 0.15


class AdaptiveSecurityToolkit:
    """Tools for adaptive security threshold management."""

    def __init__(
        self,
        siem_client: Any | None = None,
        metrics_store: Any | None = None,
        policy_engine: Any | None = None,
    ) -> None:
        self._siem_client = siem_client
        self._metrics_store = metrics_store
        self._policy_engine = policy_engine

    async def compute_baselines(
        self,
        entity_type: str = "host",
        window_hours: int = 24,
    ) -> list[BaselineMetrics]:
        """Calculate statistical baselines for risk metrics.

        Uses the metrics store if available, otherwise returns mock baselines
        with simulated current values.
        """
        logger.info(
            "adaptive_security.compute_baselines",
            entity_type=entity_type,
            window_hours=window_hours,
        )
        if self._metrics_store is not None:
            try:
                raw = await self._metrics_store.get_baselines(
                    entity_type=entity_type,
                    window_hours=window_hours,
                )
                return [BaselineMetrics(**r) for r in raw]
            except Exception:
                logger.exception("adaptive_security.compute_baselines.error")

        # Mock fallback — generate baselines with simulated drift
        defaults = _DEFAULT_BASELINES.get(entity_type, _DEFAULT_BASELINES["host"])
        baselines: list[BaselineMetrics] = []
        for metric_def in defaults:
            baseline_val = metric_def["baseline_value"]
            # Simulate current value with some noise
            noise = random.gauss(0, baseline_val * _MOCK_STD_FRACTION)
            current_val = max(0.0, baseline_val + noise)
            drift_pct = ((current_val - baseline_val) / baseline_val * 100) if baseline_val else 0.0

            baselines.append(
                BaselineMetrics(
                    entity_type=entity_type,
                    metric_name=metric_def.get("metric_name", "unknown"),
                    current_value=round(current_val, 4),
                    baseline_value=baseline_val,
                    drift_pct=round(drift_pct, 2),
                    window_hours=window_hours,
                )
            )
        return baselines

    async def detect_drift(
        self,
        baselines: list[BaselineMetrics],
    ) -> list[BaselineMetrics]:
        """Identify metrics that have drifted significantly from baseline (>2 sigma).

        Returns only the baselines where drift exceeds the threshold.
        """
        logger.info(
            "adaptive_security.detect_drift",
            baseline_count=len(baselines),
        )
        if self._metrics_store is not None:
            try:
                raw = await self._metrics_store.detect_drift(
                    baselines=[b.model_dump() for b in baselines]
                )
                return [BaselineMetrics(**r) for r in raw]
            except Exception:
                logger.exception("adaptive_security.detect_drift.error")

        # Mock fallback — drift detection based on percentage
        sigma_pct = _DRIFT_SIGMA * _MOCK_STD_FRACTION * 100  # 30%
        drifted: list[BaselineMetrics] = []
        for b in baselines:
            if abs(b.drift_pct) > sigma_pct:
                drifted.append(b)
        return drifted

    async def propose_threshold_adjustment(
        self,
        drifted_metric: BaselineMetrics,
        threat_context: ThreatContext = ThreatContext.NORMAL,
    ) -> ThresholdProposal:
        """Propose a new threshold based on drift direction and threat context.

        Applies context-aware multipliers:
        - active_attack: tighten thresholds (lower risk score thresholds)
        - post_incident: moderately tighten
        - elevated: slightly tighten
        - normal: follow the drift direction
        """
        logger.info(
            "adaptive_security.propose_threshold_adjustment",
            metric=drifted_metric.metric_name,
            drift_pct=drifted_metric.drift_pct,
            threat_context=threat_context,
        )

        # Map metric name to threshold type
        type_map: dict[str, ThresholdType] = {
            "risk_score": ThresholdType.RISK_SCORE,
            "alert_volume": ThresholdType.ALERT_VOLUME,
            "anomaly_sensitivity": ThresholdType.ANOMALY_SENSITIVITY,
            "response_urgency": ThresholdType.RESPONSE_URGENCY,
        }
        threshold_type = type_map.get(drifted_metric.metric_name, ThresholdType.RISK_SCORE)

        # Context multipliers: how aggressively to adjust
        context_multiplier: dict[ThreatContext, float] = {
            ThreatContext.NORMAL: 0.5,
            ThreatContext.ELEVATED: 0.7,
            ThreatContext.ACTIVE_ATTACK: 1.0,
            ThreatContext.POST_INCIDENT: 0.8,
        }
        multiplier = context_multiplier.get(threat_context, 0.5)

        # Calculate proposed value
        drift_direction = 1.0 if drifted_metric.drift_pct > 0 else -1.0
        adjustment_magnitude = abs(drifted_metric.drift_pct) / 100.0 * multiplier
        proposed_value = drifted_metric.baseline_value * (
            1.0 + drift_direction * adjustment_magnitude
        )
        proposed_value = round(max(0.0, min(proposed_value, 1.0)), 4)

        # Confidence inversely related to drift magnitude
        confidence = round(max(0.3, 1.0 - abs(drifted_metric.drift_pct) / 200.0), 4)

        # Risk assessment
        if abs(drifted_metric.drift_pct) > 50:
            risk = "high"
        elif abs(drifted_metric.drift_pct) > 30:
            risk = "medium"
        else:
            risk = "low"

        reasoning = (
            f"Metric '{drifted_metric.metric_name}' drifted {drifted_metric.drift_pct:.1f}% "
            f"from baseline {drifted_metric.baseline_value:.4f}. "
            f"Context: {threat_context.value}, multiplier: {multiplier}. "
            f"Proposed adjustment: {drifted_metric.baseline_value:.4f} -> {proposed_value:.4f}."
        )

        return ThresholdProposal(
            threshold_type=threshold_type,
            current_value=drifted_metric.current_value,
            proposed_value=proposed_value,
            reasoning=reasoning,
            confidence=confidence,
            risk=risk,
        )

    async def evaluate_proposal(
        self,
        proposal: ThresholdProposal,
        dry_run_hours: int = 4,
    ) -> AdaptationResult:
        """Simulate the adjustment impact via dry-run evaluation.

        Uses the policy engine if available, otherwise returns mock evaluation
        based on proposal confidence and risk.
        """
        logger.info(
            "adaptive_security.evaluate_proposal",
            threshold_type=proposal.threshold_type.value,
            proposed_value=proposal.proposed_value,
            dry_run_hours=dry_run_hours,
        )

        proposal_id = hashlib.sha256(
            f"{proposal.threshold_type.value}:{proposal.proposed_value}:{time.time()}".encode()
        ).hexdigest()[:12]

        if self._policy_engine is not None:
            try:
                raw = await self._policy_engine.evaluate(
                    proposal=proposal.model_dump(),
                    dry_run_hours=dry_run_hours,
                )
                return AdaptationResult(proposal_id=proposal_id, **raw)
            except Exception:
                logger.exception("adaptive_security.evaluate_proposal.error")

        # Mock evaluation — accept if confidence is high enough and risk is acceptable
        accepted = proposal.confidence >= 0.5 and proposal.risk != "high"

        # Simulate impact metrics
        if accepted:
            fp_delta = round(random.uniform(-0.15, -0.02), 4)
            det_delta = round(random.uniform(0.01, 0.10), 4)
            impact = "Threshold adjustment reduces false positives while maintaining detection rate"
        else:
            fp_delta = round(random.uniform(0.0, 0.05), 4)
            det_delta = round(random.uniform(-0.10, -0.01), 4)
            impact = "Adjustment rejected: risk too high or confidence too low"

        return AdaptationResult(
            proposal_id=proposal_id,
            accepted=accepted,
            actual_impact=impact,
            false_positive_delta=fp_delta,
            detection_delta=det_delta,
        )

    async def apply_adjustment(
        self,
        proposal: ThresholdProposal,
    ) -> dict[str, Any]:
        """Apply an accepted threshold adjustment.

        Persists the new threshold to the metrics store if available.
        """
        logger.info(
            "adaptive_security.apply_adjustment",
            threshold_type=proposal.threshold_type.value,
            new_value=proposal.proposed_value,
        )

        if self._metrics_store is not None:
            try:
                await self._metrics_store.update_threshold(
                    threshold_type=proposal.threshold_type.value,
                    new_value=proposal.proposed_value,
                )
                return {
                    "applied": True,
                    "threshold_type": proposal.threshold_type.value,
                    "new_value": proposal.proposed_value,
                    "timestamp": time.time(),
                }
            except Exception:
                logger.exception("adaptive_security.apply_adjustment.error")

        # Mock fallback
        return {
            "applied": True,
            "threshold_type": proposal.threshold_type.value,
            "new_value": proposal.proposed_value,
            "previous_value": proposal.current_value,
            "timestamp": time.time(),
            "mock": True,
        }
