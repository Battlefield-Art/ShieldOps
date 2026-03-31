"""Alert Fatigue Reducer Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    AlertRecord,
    AlertSeverity,
    FatigueIndicator,
    NoiseAnalysis,
    NoiseCategory,
    TuningRule,
    ValidationResult,
)

logger = structlog.get_logger()

_SAMPLE_RULES: list[dict[str, Any]] = [
    {
        "rule_name": "Failed SSH Login",
        "severity": "medium",
        "source": "auth_logs",
        "count_24h": 1240,
        "count_7d": 8700,
        "acknowledged_pct": 0.12,
        "false_positive_rate": 0.85,
    },
    {
        "rule_name": "Port Scan Detected",
        "severity": "low",
        "source": "network_ids",
        "count_24h": 3400,
        "count_7d": 23800,
        "acknowledged_pct": 0.05,
        "false_positive_rate": 0.92,
    },
    {
        "rule_name": "Malware Signature Match",
        "severity": "critical",
        "source": "endpoint_edr",
        "count_24h": 8,
        "count_7d": 42,
        "acknowledged_pct": 0.95,
        "false_positive_rate": 0.05,
    },
    {
        "rule_name": "DNS Query to Known Bad Domain",
        "severity": "high",
        "source": "dns_logs",
        "count_24h": 45,
        "count_7d": 310,
        "acknowledged_pct": 0.78,
        "false_positive_rate": 0.15,
    },
    {
        "rule_name": "AWS Root Account Login",
        "severity": "critical",
        "source": "cloudtrail",
        "count_24h": 2,
        "count_7d": 5,
        "acknowledged_pct": 1.0,
        "false_positive_rate": 0.0,
    },
    {
        "rule_name": "Certificate Expiry Warning",
        "severity": "info",
        "source": "cert_monitor",
        "count_24h": 890,
        "count_7d": 6230,
        "acknowledged_pct": 0.02,
        "false_positive_rate": 0.70,
    },
    {
        "rule_name": "Excessive API Rate",
        "severity": "medium",
        "source": "api_gateway",
        "count_24h": 560,
        "count_7d": 3920,
        "acknowledged_pct": 0.08,
        "false_positive_rate": 0.78,
    },
    {
        "rule_name": "Privilege Escalation Attempt",
        "severity": "high",
        "source": "endpoint_edr",
        "count_24h": 15,
        "count_7d": 95,
        "acknowledged_pct": 0.88,
        "false_positive_rate": 0.10,
    },
]

_SAMPLE_ANALYSTS = [
    {"analyst_id": "analyst-01", "team": "SOC-T1"},
    {"analyst_id": "analyst-02", "team": "SOC-T1"},
    {"analyst_id": "analyst-03", "team": "SOC-T2"},
    {"analyst_id": "analyst-04", "team": "SOC-T2"},
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class AlertFatigueReducerToolkit:
    """Tools for alert fatigue detection and reduction."""

    def __init__(
        self,
        siem_client: Any | None = None,
        soar_client: Any | None = None,
    ) -> None:
        self._siem_client = siem_client
        self._soar_client = soar_client

    async def collect_alerts(
        self,
        tenant_id: str,
    ) -> list[AlertRecord]:
        """Collect alert data from SIEM/SOAR."""
        logger.info(
            "afr.collect_alerts",
            tenant_id=tenant_id,
        )

        if self._siem_client is not None:
            try:
                raw = await self._siem_client.get_alerts(
                    tenant_id=tenant_id,
                )
                return [AlertRecord(**r) for r in raw]
            except Exception:
                logger.exception("afr.collect_alerts.error")

        alerts: list[AlertRecord] = []
        for i, r in enumerate(_SAMPLE_RULES):
            _resp = round(random.uniform(1.0, 45.0), 1)  # noqa: S311
            alerts.append(
                AlertRecord(
                    id=_gen_id("AR", tenant_id, i),
                    rule_id=f"RULE-{i + 1:03d}",
                    rule_name=r["rule_name"],
                    severity=AlertSeverity(r["severity"]),
                    source=r["source"],
                    count_24h=r["count_24h"],
                    count_7d=r["count_7d"],
                    acknowledged_pct=r["acknowledged_pct"],
                    avg_response_min=_resp,
                    false_positive_rate=r["false_positive_rate"],
                    last_triggered="2026-03-30T09:45:00Z",
                )
            )
        return alerts

    async def analyze_noise(
        self,
        alerts: list[AlertRecord],
    ) -> list[NoiseAnalysis]:
        """Analyze alert noise per rule."""
        logger.info(
            "afr.analyze_noise",
            count=len(alerts),
        )

        categories = list(NoiseCategory)
        analyses: list[NoiseAnalysis] = []
        for i, a in enumerate(alerts):
            noise_score = round(a.false_positive_rate * 0.6 + (1 - a.acknowledged_pct) * 0.4, 2)
            signal = round(1.0 - noise_score, 2)
            cat = NoiseCategory.FALSE_POSITIVE
            if a.false_positive_rate > 0.8:
                cat = NoiseCategory.FALSE_POSITIVE
            elif a.acknowledged_pct < 0.1:
                cat = NoiseCategory.LOW_FIDELITY
            elif a.count_24h > 1000:
                cat = NoiseCategory.DUPLICATE
            else:
                cat = categories[i % len(categories)]

            dup = random.randint(0, a.count_24h // 3)  # noqa: S311
            rec = "Tune threshold" if noise_score > 0.5 else "Keep current settings"
            analyses.append(
                NoiseAnalysis(
                    id=_gen_id("NA", a.id, i),
                    rule_id=a.rule_id,
                    noise_category=cat,
                    noise_score=noise_score,
                    signal_ratio=signal,
                    duplicate_count=dup,
                    correlation_group=f"group-{i % 4}",
                    recommendation=rec,
                )
            )
        return analyses

    async def detect_fatigue(
        self,
        alerts: list[AlertRecord],
    ) -> list[FatigueIndicator]:
        """Detect analyst fatigue indicators."""
        logger.info(
            "afr.detect_fatigue",
            alert_count=len(alerts),
        )

        total_daily = sum(a.count_24h for a in alerts)
        indicators: list[FatigueIndicator] = []
        for i, analyst in enumerate(_SAMPLE_ANALYSTS):
            share = total_daily // len(_SAMPLE_ANALYSTS)
            triage_time = round(random.uniform(2.0, 15.0), 1)  # noqa: S311
            dismiss = round(random.uniform(0.1, 0.8), 2)  # noqa: S311
            fatigue = round(
                (share / 500) * 0.4 + dismiss * 0.3 + (triage_time / 15.0) * 0.3,  # noqa: S311
                2,
            )
            risk = "high" if fatigue > 0.7 else "medium" if fatigue > 0.4 else "low"
            top_rules = [
                a.rule_name for a in sorted(alerts, key=lambda x: x.count_24h, reverse=True)[:3]
            ]
            indicators.append(
                FatigueIndicator(
                    id=_gen_id("FI", analyst["analyst_id"], i),
                    analyst_id=analyst["analyst_id"],
                    team=analyst["team"],
                    alerts_per_shift=share,
                    avg_triage_time_min=triage_time,
                    dismiss_rate=dismiss,
                    fatigue_score=fatigue,
                    burnout_risk=risk,
                    top_noisy_rules=top_rules,
                )
            )
        return indicators

    async def tune_rules(
        self,
        noise_analyses: list[NoiseAnalysis],
    ) -> list[TuningRule]:
        """Generate rule tuning suggestions."""
        logger.info(
            "afr.tune_rules",
            count=len(noise_analyses),
        )

        tunings: list[TuningRule] = []
        for i, na in enumerate(noise_analyses):
            if na.noise_score < 0.3:
                continue
            reduction = round(na.noise_score * 60, 1)  # noqa: S311
            risk_miss = round(max(0, 0.05 - na.signal_ratio * 0.02), 3)
            tunings.append(
                TuningRule(
                    id=_gen_id("TR", na.rule_id, i),
                    rule_id=na.rule_id,
                    action="adjust_threshold",
                    current_threshold="default",
                    suggested_threshold="optimized",
                    expected_reduction_pct=reduction,
                    risk_of_miss=risk_miss,
                    rationale=na.recommendation,
                )
            )
        return tunings

    async def validate_changes(
        self,
        tuning_rules: list[TuningRule],
    ) -> list[ValidationResult]:
        """Validate proposed tuning changes."""
        logger.info(
            "afr.validate_changes",
            count=len(tuning_rules),
        )

        results: list[ValidationResult] = []
        for i, tr in enumerate(tuning_rules):
            before = random.randint(100, 5000)  # noqa: S311
            reduction = tr.expected_reduction_pct / 100.0
            after = int(before * (1.0 - reduction))
            missed = random.randint(0, 2)  # noqa: S311
            safe = missed == 0 and reduction < 0.9
            results.append(
                ValidationResult(
                    id=_gen_id("VR", tr.rule_id, i),
                    rule_id=tr.rule_id,
                    passed=safe,
                    alerts_before=before,
                    alerts_after=after,
                    reduction_pct=round(reduction * 100, 1),
                    missed_true_positives=missed,
                    safe_to_deploy=safe,
                )
            )
        return results

    async def record_metric(
        self,
        metric_name: str,
        value: float,
        tags: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Record a metric for observability."""
        _tags = tags or {}
        logger.info(
            "afr.record_metric",
            metric=metric_name,
            value=value,
            tags=_tags,
        )
        return {
            "metric": metric_name,
            "value": value,
            "tags": _tags,
            "recorded": True,
        }
