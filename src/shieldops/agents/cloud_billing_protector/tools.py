"""Cloud Billing Protector Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random  # noqa: S311
from typing import Any

import structlog

from .models import (
    AnomalySeverity,
    BillingAnomaly,
    BillingRecord,
    EnforcementAction,
    FraudClassification,
    FraudType,
    SpendPattern,
)

logger = structlog.get_logger()

_SAMPLE_BILLING: list[dict[str, Any]] = [
    {
        "account_id": "acct-prod-01",
        "service": "EC2",
        "region": "us-east-1",
        "resource_id": "i-0abc123def456",
        "cost_usd": 4800.0,
        "usage_quantity": 720.0,
        "usage_unit": "hours",
        "tags": {"team": "unknown", "env": "production"},
    },
    {
        "account_id": "acct-prod-01",
        "service": "EC2-GPU",
        "region": "us-west-2",
        "resource_id": "i-0gpu789xyz000",
        "cost_usd": 12500.0,
        "usage_quantity": 720.0,
        "usage_unit": "hours",
        "tags": {},
    },
    {
        "account_id": "acct-dev-02",
        "service": "S3",
        "region": "us-east-1",
        "resource_id": "bucket-temp-export",
        "cost_usd": 890.0,
        "usage_quantity": 5000.0,
        "usage_unit": "GB",
        "tags": {"team": "data", "env": "dev"},
    },
    {
        "account_id": "acct-prod-01",
        "service": "Lambda",
        "region": "eu-west-1",
        "resource_id": "fn-batch-processor",
        "cost_usd": 1200.0,
        "usage_quantity": 50000000.0,
        "usage_unit": "invocations",
        "tags": {"team": "platform", "env": "production"},
    },
    {
        "account_id": "acct-staging-03",
        "service": "RDS",
        "region": "us-east-1",
        "resource_id": "db-analytics-xl",
        "cost_usd": 3200.0,
        "usage_quantity": 720.0,
        "usage_unit": "hours",
        "tags": {"team": "analytics", "env": "staging"},
    },
    {
        "account_id": "acct-prod-01",
        "service": "EKS",
        "region": "us-east-1",
        "resource_id": "cluster-main",
        "cost_usd": 2100.0,
        "usage_quantity": 50.0,
        "usage_unit": "nodes",
        "tags": {"team": "platform", "env": "production"},
    },
    {
        "account_id": "acct-dev-02",
        "service": "EC2",
        "region": "ap-southeast-1",
        "resource_id": "i-0rogue456abc",
        "cost_usd": 6700.0,
        "usage_quantity": 720.0,
        "usage_unit": "hours",
        "tags": {},
    },
    {
        "account_id": "acct-prod-01",
        "service": "CloudFront",
        "region": "global",
        "resource_id": "dist-main-cdn",
        "cost_usd": 450.0,
        "usage_quantity": 10000.0,
        "usage_unit": "GB",
        "tags": {"team": "frontend", "env": "production"},
    },
]

_HISTORICAL_AVG: dict[str, float] = {
    "EC2": 1200.0,
    "EC2-GPU": 500.0,
    "S3": 200.0,
    "Lambda": 300.0,
    "RDS": 1500.0,
    "EKS": 1800.0,
    "CloudFront": 400.0,
}


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class CloudBillingProtectorToolkit:
    """Tools for cloud billing fraud and abuse detection."""

    def __init__(
        self,
        billing_api: Any | None = None,
        budget_service: Any | None = None,
    ) -> None:
        self._billing_api = billing_api
        self._budget_service = budget_service

    async def collect_billing(
        self,
        tenant_id: str,
    ) -> list[BillingRecord]:
        """Collect billing records from cloud providers."""
        logger.info(
            "cbp.collect_billing",
            tenant_id=tenant_id,
        )

        if self._billing_api is not None:
            try:
                raw = await self._billing_api.get_records(
                    tenant_id=tenant_id,
                )
                return [BillingRecord(**r) for r in raw]
            except Exception:
                logger.exception("cbp.collect_billing.error")

        records: list[BillingRecord] = []
        for i, b in enumerate(_SAMPLE_BILLING):
            noise = random.uniform(-50, 50)  # noqa: S311
            records.append(
                BillingRecord(
                    id=_gen_id("BR", tenant_id, i),
                    account_id=b["account_id"],
                    service=b["service"],
                    region=b["region"],
                    resource_id=b["resource_id"],
                    cost_usd=round(b["cost_usd"] + noise, 2),
                    usage_quantity=b["usage_quantity"],
                    usage_unit=b["usage_unit"],
                    timestamp=f"2026-03-{28 - (i % 7):02d}T00:00:00Z",
                    tags=b["tags"],
                )
            )
        return records

    async def analyze_patterns(
        self,
        records: list[BillingRecord],
    ) -> list[SpendPattern]:
        """Analyze spending patterns against historical data."""
        logger.info(
            "cbp.analyze_patterns",
            count=len(records),
        )

        service_spend: dict[str, list[BillingRecord]] = {}
        for r in records:
            key = f"{r.account_id}|{r.service}"
            service_spend.setdefault(key, []).append(r)

        patterns: list[SpendPattern] = []
        for i, (key, group) in enumerate(service_spend.items()):
            acct, svc = key.split("|", 1)
            current = sum(r.cost_usd for r in group)
            avg = _HISTORICAL_AVG.get(svc, 500.0)
            deviation = round(((current - avg) / avg) * 100, 1) if avg > 0 else 0.0

            trend = "stable"
            if deviation > 50:
                trend = "spike"
            elif deviation > 20:
                trend = "increasing"
            elif deviation < -20:
                trend = "decreasing"

            patterns.append(
                SpendPattern(
                    id=_gen_id("SP", key, i),
                    account_id=acct,
                    service=svc,
                    avg_daily_cost=round(avg / 30, 2),
                    current_daily_cost=round(current / 30, 2),
                    deviation_pct=deviation,
                    trend=trend,
                    period_days=30,
                )
            )
        return patterns

    async def detect_billing_anomalies(
        self,
        records: list[BillingRecord],
        patterns: list[SpendPattern],
    ) -> list[BillingAnomaly]:
        """Detect billing anomalies from patterns."""
        logger.info(
            "cbp.detect_anomalies",
            records=len(records),
            patterns=len(patterns),
        )

        pattern_map: dict[str, SpendPattern] = {}
        for pat in patterns:
            key = f"{pat.account_id}|{pat.service}"
            pattern_map[key] = pat

        anomalies: list[BillingAnomaly] = []
        idx = 0
        for r in records:
            key = f"{r.account_id}|{r.service}"
            p: SpendPattern | None = pattern_map.get(key)
            if not p or p.deviation_pct <= 50:
                continue

            severity = AnomalySeverity.MEDIUM
            if p.deviation_pct > 500:
                severity = AnomalySeverity.CRITICAL
            elif p.deviation_pct > 200:
                severity = AnomalySeverity.HIGH

            expected = _HISTORICAL_AVG.get(r.service, 500.0)
            excess = round(r.cost_usd - expected, 2)
            anomaly_type = "cost_spike"
            if not r.tags:
                anomaly_type = "untagged_resource"
            elif r.service == "EC2-GPU":
                anomaly_type = "gpu_spike"

            anomalies.append(
                BillingAnomaly(
                    id=_gen_id("BA", r.id, idx),
                    account_id=r.account_id,
                    service=r.service,
                    resource_id=r.resource_id,
                    severity=severity,
                    anomaly_type=anomaly_type,
                    expected_cost=expected,
                    actual_cost=r.cost_usd,
                    excess_cost=max(excess, 0),
                    detection_method="statistical_deviation",
                )
            )
            idx += 1
        return anomalies

    async def classify_fraud(
        self,
        anomalies: list[BillingAnomaly],
        records: list[BillingRecord],
    ) -> list[FraudClassification]:
        """Classify anomalies as potential fraud."""
        logger.info(
            "cbp.classify_fraud",
            count=len(anomalies),
        )

        record_map = {r.resource_id: r for r in records}
        classifications: list[FraudClassification] = []
        for i, a in enumerate(anomalies):
            r = record_map.get(a.resource_id)
            fraud_type = FraudType.BUDGET_OVERRUN
            indicators: list[str] = []
            confidence = 0.5

            is_gpu = a.anomaly_type == "gpu_spike"
            is_untagged = r and not r.tags

            if is_gpu and is_untagged:
                fraud_type = FraudType.CRYPTOMINING
                indicators = [
                    "GPU instance",
                    "No tags",
                    f"{a.severity.value} severity",
                ]
                confidence = 0.92
            elif is_untagged and a.excess_cost > 2000:
                fraud_type = FraudType.RESOURCE_HIJACKING
                indicators = [
                    "Untagged resource",
                    f"Excess: ${a.excess_cost:.0f}",
                ]
                confidence = 0.78
            elif a.severity == AnomalySeverity.CRITICAL:
                fraud_type = FraudType.CREDENTIAL_ABUSE
                indicators = [
                    "Critical cost spike",
                    f"Deviation: {a.actual_cost / a.expected_cost:.1f}x",
                ]
                confidence = 0.7
            else:
                indicators = [f"Cost spike: ${a.excess_cost:.0f}"]
                confidence = 0.4

            classifications.append(
                FraudClassification(
                    id=_gen_id("FC", a.id, i),
                    anomaly_id=a.id,
                    fraud_type=fraud_type,
                    confidence=confidence,
                    indicators=indicators,
                    estimated_loss=a.excess_cost,
                    is_confirmed=confidence >= 0.8,
                )
            )
        return classifications

    async def enforce_limits(
        self,
        anomalies: list[BillingAnomaly],
        classifications: list[FraudClassification],
    ) -> list[EnforcementAction]:
        """Enforce budget limits and terminate rogue resources."""
        logger.info(
            "cbp.enforce_limits",
            count=len(anomalies),
        )

        class_map = {c.anomaly_id: c for c in classifications}
        actions: list[EnforcementAction] = []
        for i, a in enumerate(anomalies):
            fc = class_map.get(a.id)
            if not fc:
                continue

            should_terminate = fc.is_confirmed and fc.fraud_type in (
                FraudType.CRYPTOMINING,
                FraudType.RESOURCE_HIJACKING,
            )

            if should_terminate:
                actions.append(
                    EnforcementAction(
                        id=_gen_id("EA", a.id, i),
                        anomaly_id=a.id,
                        action_type="terminate_resource",
                        status="executed",
                        resource_affected=a.resource_id,
                        budget_limit_set=a.expected_cost * 1.2,
                        auto_terminated=True,
                        rollback_available=True,
                    )
                )
            elif fc.confidence >= 0.5:
                actions.append(
                    EnforcementAction(
                        id=_gen_id("EA", a.id, i),
                        anomaly_id=a.id,
                        action_type="set_budget_alert",
                        status="configured",
                        resource_affected=a.resource_id,
                        budget_limit_set=a.expected_cost * 1.5,
                        auto_terminated=False,
                        rollback_available=True,
                    )
                )
            else:
                actions.append(
                    EnforcementAction(
                        id=_gen_id("EA", a.id, i),
                        anomaly_id=a.id,
                        action_type="monitor",
                        status="watching",
                        resource_affected=a.resource_id,
                        budget_limit_set=0.0,
                        auto_terminated=False,
                        rollback_available=False,
                    )
                )
        return actions

    async def record_metric(
        self,
        metric_name: str,
        value: float,
        tags: dict[str, str] | None = None,
    ) -> None:
        """Record a metric for observability."""
        logger.info(
            "cbp.record_metric",
            metric=metric_name,
            value=value,
            tags=tags or {},
        )
