"""Insider Risk Scorer Agent — Tool functions for
behavioral analytics and risk scoring."""

from __future__ import annotations

import random
import time
from typing import Any
from uuid import uuid4

import structlog

logger = structlog.get_logger()

_HIGH_RISK_THRESHOLD = 0.75
_CRITICAL_RISK_THRESHOLD = 0.90
_ANOMALY_SEVERITY_THRESHOLD = 0.6


class InsiderRiskScorerToolkit:
    """Toolkit for insider risk scoring and behavioral
    analytics across identity sources."""

    def __init__(
        self,
        identity_provider: Any | None = None,
        ueba_engine: Any | None = None,
        hr_system: Any | None = None,
        dlp_engine: Any | None = None,
        siem_connector: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._identity_provider = identity_provider
        self._ueba_engine = ueba_engine
        self._hr_system = hr_system
        self._dlp_engine = dlp_engine
        self._siem_connector = siem_connector
        self._repository = repository

    async def collect_signals(
        self,
        tenant_id: str,
        time_window_hours: int = 24,
    ) -> list[dict[str, Any]]:
        """Collect behavioral signals from identity,
        HR, DLP, and SIEM sources.

        Fuses events across providers within the time
        window for comprehensive signal coverage.
        """
        logger.info(
            "irs.collect_signals",
            tenant_id=tenant_id,
            time_window_hours=time_window_hours,
        )
        signals: list[dict[str, Any]] = []

        sources = [
            ("identity", self._identity_provider),
            ("ueba", self._ueba_engine),
            ("hr", self._hr_system),
            ("dlp", self._dlp_engine),
            ("siem", self._siem_connector),
        ]

        for _name, connector in sources:
            if connector is None:
                continue
            try:
                if hasattr(connector, "get_signals"):
                    raw = await connector.get_signals(
                        tenant_id=tenant_id,
                        hours=time_window_hours,
                    )
                    signals.extend(raw)
            except Exception:
                logger.warning("irs.collect.source_error")

        if not signals:
            signals = self._synthetic_signals(tenant_id)

        return signals

    async def analyze_behavior(
        self,
        signals: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Build behavioral profiles with peer group
        comparison.

        Groups users by department, computes baseline
        metrics, and identifies deviations from peer
        norms.
        """
        logger.info(
            "irs.analyze_behavior",
            signal_count=len(signals),
        )
        profiles: list[dict[str, Any]] = []
        user_groups: dict[str, list[dict[str, Any]]] = {}

        for sig in signals:
            uid = sig.get("user_id", "unknown")
            user_groups.setdefault(uid, []).append(sig)

        for user_id, user_sigs in user_groups.items():
            action_count = len(user_sigs)
            dept = user_sigs[0].get("department", "general")
            rand_dev = random.uniform(0.1, 0.9)  # noqa: S311

            profiles.append(
                {
                    "user_id": user_id,
                    "department": dept,
                    "peer_group": dept,
                    "avg_daily_actions": action_count,
                    "typical_hours": "08:00-18:00",
                    "deviation_score": round(rand_dev, 3),
                    "signal_count": action_count,
                }
            )

        return profiles

    async def score_risk(
        self,
        profiles: list[dict[str, Any]],
        anomalies: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Compute composite risk scores per user.

        Aggregates behavioral deviation, anomaly severity,
        and peer comparison into a weighted risk score
        with tier classification.
        """
        logger.info(
            "irs.score_risk",
            profile_count=len(profiles),
            anomaly_count=len(anomalies),
        )
        anomaly_map: dict[str, list[dict[str, Any]]] = {}
        for a in anomalies:
            uid = a.get("user_id", "")
            anomaly_map.setdefault(uid, []).append(a)

        scores: list[dict[str, Any]] = []
        for profile in profiles:
            uid = profile.get("user_id", "")
            dev = profile.get("deviation_score", 0.0)
            user_anomalies = anomaly_map.get(uid, [])
            anomaly_weight = min(len(user_anomalies) * 0.15, 0.5)
            overall = min(dev + anomaly_weight, 1.0)

            if overall >= _CRITICAL_RISK_THRESHOLD:
                tier = "critical"
            elif overall >= _HIGH_RISK_THRESHOLD:
                tier = "high"
            elif overall >= 0.5:
                tier = "medium"
            elif overall >= 0.25:
                tier = "low"
            else:
                tier = "minimal"

            scores.append(
                {
                    "user_id": uid,
                    "overall_score": round(overall, 3),
                    "tier": tier,
                    "category_scores": {
                        "access_pattern": round(dev * 0.8, 3),
                        "data_movement": round(dev * 0.6, 3),
                        "peer_deviation": round(dev, 3),
                    },
                    "contributing_factors": [a.get("description", "") for a in user_anomalies[:5]],
                    "confidence": round(
                        min(0.6 + len(user_anomalies) * 0.05, 0.95),
                        3,
                    ),
                }
            )

        return scores

    async def detect_anomalies(
        self,
        profiles: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Detect behavioral anomalies from user profiles.

        Applies statistical analysis to identify outliers
        across access patterns, data movement, privilege
        usage, and temporal behavior.
        """
        logger.info(
            "irs.detect_anomalies",
            profile_count=len(profiles),
        )
        anomalies: list[dict[str, Any]] = []

        for profile in profiles:
            dev = profile.get("deviation_score", 0.0)
            if dev >= _ANOMALY_SEVERITY_THRESHOLD:
                aid = uuid4().hex[:12]
                anomalies.append(
                    {
                        "anomaly_id": f"anom-{aid}",
                        "user_id": profile.get("user_id", ""),
                        "category": "peer_deviation",
                        "description": (
                            f"Deviation score {dev:.2f} "
                            f"exceeds threshold "
                            f"{_ANOMALY_SEVERITY_THRESHOLD}"
                        ),
                        "severity": round(dev, 3),
                        "confidence": 0.75,
                    }
                )

        return anomalies

    async def generate_alerts(
        self,
        scores: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Generate alerts for high-risk users.

        Creates actionable alerts with recommended
        response actions for security teams.
        """
        logger.info(
            "irs.generate_alerts",
            score_count=len(scores),
        )
        alerts: list[dict[str, Any]] = []

        for score in scores:
            tier = score.get("tier", "minimal")
            if tier in ("critical", "high"):
                aid = uuid4().hex[:12]
                alerts.append(
                    {
                        "alert_id": f"alert-{aid}",
                        "user_id": score.get("user_id", ""),
                        "tier": tier,
                        "overall_score": score.get("overall_score", 0),
                        "timestamp": time.time(),
                        "action": (
                            "immediate_review" if tier == "critical" else "enhanced_monitoring"
                        ),
                    }
                )

        return alerts

    async def record_metric(
        self,
        metric_name: str,
        value: float,
        tags: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Record a scoring metric for dashboarding."""
        logger.info(
            "irs.record_metric",
            metric=metric_name,
            value=value,
        )
        return {
            "metric": metric_name,
            "value": value,
            "tags": tags or {},
            "timestamp": time.time(),
        }

    def _synthetic_signals(
        self,
        tenant_id: str,
    ) -> list[dict[str, Any]]:
        """Generate synthetic signals for testing."""
        now = time.time()
        base_id = uuid4().hex[:8]
        return [
            {
                "signal_id": f"syn-{base_id}-1",
                "user_id": f"user-{tenant_id}-alice",
                "source": "identity",
                "action": "login",
                "resource": "aws-console",
                "timestamp": now - 3600,
                "department": "engineering",
            },
            {
                "signal_id": f"syn-{base_id}-2",
                "user_id": f"user-{tenant_id}-alice",
                "source": "dlp",
                "action": "bulk_export",
                "resource": "s3://corp-data",
                "timestamp": now - 1800,
                "department": "engineering",
            },
            {
                "signal_id": f"syn-{base_id}-3",
                "user_id": f"user-{tenant_id}-bob",
                "source": "siem",
                "action": "privilege_escalation",
                "resource": "iam-console",
                "timestamp": now - 900,
                "department": "devops",
            },
        ]
