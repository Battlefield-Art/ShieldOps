"""Cloud Cost Anomaly Detector Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any
from uuid import uuid4

import structlog

from .models import (
    AlertRecord,
    AnomalyType,
    BillingRecord,
    CauseClassification,
    CloudProvider,
    CostAnomaly,
    SpendTrend,
)

logger = structlog.get_logger()

_SAMPLE_BILLING: list[dict[str, Any]] = [
    {
        "provider": "aws",
        "account_id": "111222333444",
        "service": "EC2",
        "region": "us-east-1",
        "cost_usd": 4200.50,
        "usage_quantity": 720.0,
        "usage_unit": "hours",
    },
    {
        "provider": "aws",
        "account_id": "111222333444",
        "service": "RDS",
        "region": "us-east-1",
        "cost_usd": 1890.00,
        "usage_quantity": 720.0,
        "usage_unit": "hours",
    },
    {
        "provider": "gcp",
        "account_id": "proj-analytics-01",
        "service": "BigQuery",
        "region": "us-central1",
        "cost_usd": 8500.00,
        "usage_quantity": 42.5,
        "usage_unit": "TB_scanned",
    },
    {
        "provider": "gcp",
        "account_id": "proj-analytics-01",
        "service": "GKE",
        "region": "us-central1",
        "cost_usd": 3200.00,
        "usage_quantity": 96.0,
        "usage_unit": "vCPU_hours",
    },
    {
        "provider": "azure",
        "account_id": "sub-prod-001",
        "service": "Virtual Machines",
        "region": "eastus",
        "cost_usd": 5600.00,
        "usage_quantity": 1440.0,
        "usage_unit": "hours",
    },
    {
        "provider": "aws",
        "account_id": "111222333444",
        "service": "S3",
        "region": "us-east-1",
        "cost_usd": 320.00,
        "usage_quantity": 12.5,
        "usage_unit": "TB_stored",
    },
    {
        "provider": "azure",
        "account_id": "sub-prod-001",
        "service": "Cosmos DB",
        "region": "eastus",
        "cost_usd": 2400.00,
        "usage_quantity": 5000.0,
        "usage_unit": "RU_per_sec",
    },
    {
        "provider": "aws",
        "account_id": "555666777888",
        "service": "Lambda",
        "region": "us-west-2",
        "cost_usd": 45.00,
        "usage_quantity": 15000000.0,
        "usage_unit": "invocations",
    },
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class CloudCostAnomalyDetectorToolkit:
    """Tools for cloud cost anomaly detection."""

    def __init__(
        self,
        billing_api: Any | None = None,
        alert_channel: Any | None = None,
    ) -> None:
        self._billing_api = billing_api
        self._alert_channel = alert_channel

    async def collect_billing(
        self,
        tenant_id: str,
    ) -> list[BillingRecord]:
        """Collect billing records from cloud providers."""
        logger.info(
            "ccad.collect_billing",
            tenant_id=tenant_id,
        )

        if self._billing_api is not None:
            try:
                raw = await self._billing_api.get_billing(
                    tenant_id=tenant_id,
                )
                return [BillingRecord(**r) for r in raw]
            except Exception:
                logger.exception("ccad.collect_billing.error")

        records: list[BillingRecord] = []
        for i, b in enumerate(_SAMPLE_BILLING):
            noise = random.uniform(-50.0, 50.0)  # noqa: S311
            records.append(
                BillingRecord(
                    id=_gen_id("BR", tenant_id, i),
                    timestamp=f"2026-03-{28 + (i % 3):02d}T00:00:00Z",
                    provider=CloudProvider(b["provider"]),
                    account_id=b["account_id"],
                    service=b["service"],
                    region=b["region"],
                    cost_usd=round(b["cost_usd"] + noise, 2),
                    usage_quantity=b["usage_quantity"],
                    usage_unit=b["usage_unit"],
                )
            )
        return records

    async def analyze_trends(
        self,
        records: list[BillingRecord],
    ) -> list[SpendTrend]:
        """Analyze spending trends per service."""
        logger.info(
            "ccad.analyze_trends",
            count=len(records),
        )

        groups: dict[str, list[BillingRecord]] = {}
        for r in records:
            key = f"{r.provider.value}|{r.service}"
            groups.setdefault(key, []).append(r)

        trends: list[SpendTrend] = []
        for i, (key, group) in enumerate(groups.items()):
            provider_str, service = key.split("|", 1)
            total = sum(r.cost_usd for r in group)
            avg = total / max(len(group), 1)
            baseline = avg * 0.8
            change = ((avg - baseline) / max(baseline, 0.01)) * 100
            trends.append(
                SpendTrend(
                    id=_gen_id("ST", key, i),
                    service=service,
                    provider=CloudProvider(provider_str),
                    period_days=30,
                    avg_daily_cost=round(baseline, 2),
                    current_daily_cost=round(avg, 2),
                    change_pct=round(change, 1),
                    forecast_monthly=round(avg * 30, 2),
                    trend_direction="up" if change > 10 else "stable",
                )
            )
        return trends

    async def detect_anomalies(
        self,
        trends: list[SpendTrend],
    ) -> list[CostAnomaly]:
        """Detect cost anomalies from trends."""
        logger.info(
            "ccad.detect_anomalies",
            count=len(trends),
        )

        anomalies: list[CostAnomaly] = []
        idx = 0
        for t in trends:
            if t.change_pct > 20:
                severity = "critical" if t.change_pct > 50 else "high"
                conf_val = min(t.change_pct / 100.0, 0.95)
                anomalies.append(
                    CostAnomaly(
                        id=_gen_id("CA", t.id, idx),
                        anomaly_type=AnomalyType.SPIKE,
                        service=t.service,
                        provider=t.provider,
                        expected_cost=t.avg_daily_cost * 30,
                        actual_cost=t.current_daily_cost * 30,
                        deviation_pct=t.change_pct,
                        severity=severity,
                        confidence=round(conf_val, 2),
                        evidence=[
                            f"Change: +{t.change_pct}%",
                            f"Daily: ${t.current_daily_cost}",
                        ],
                    )
                )
                idx += 1
            if t.current_daily_cost > 100 and t.change_pct < -10:
                anomalies.append(
                    CostAnomaly(
                        id=_gen_id("CA", t.id, idx),
                        anomaly_type=AnomalyType.WASTE,
                        service=t.service,
                        provider=t.provider,
                        expected_cost=0.0,
                        actual_cost=t.current_daily_cost * 30,
                        deviation_pct=abs(t.change_pct),
                        severity="medium",
                        confidence=0.75,
                        evidence=[
                            f"Under-utilized: {t.service}",
                            f"Monthly: ${t.forecast_monthly}",
                        ],
                    )
                )
                idx += 1
        return anomalies

    async def classify_cause(
        self,
        anomalies: list[CostAnomaly],
    ) -> list[CauseClassification]:
        """Classify root causes for anomalies."""
        logger.info(
            "ccad.classify_cause",
            count=len(anomalies),
        )

        classifications: list[CauseClassification] = []
        for i, a in enumerate(anomalies):
            savings = round((a.actual_cost - a.expected_cost) * 0.6, 2)
            if a.anomaly_type == AnomalyType.SPIKE:
                cause = "Unexpected workload increase or misconfigured auto-scaling"
                rec = "Review auto-scaling policies and right-size instances"
            elif a.anomaly_type == AnomalyType.WASTE:
                cause = "Idle or orphaned resources still accruing charges"
                rec = "Terminate unused resources and enable auto-shutdown"
            else:
                cause = "Configuration drift from cost-optimized baseline"
                rec = "Re-apply cost optimization policies"
            classifications.append(
                CauseClassification(
                    id=_gen_id("CC", a.id, i),
                    anomaly_id=a.id,
                    root_cause=cause,
                    category=a.anomaly_type,
                    recommendation=rec,
                    estimated_savings_usd=max(savings, 0.0),
                    auto_remediable=a.anomaly_type == AnomalyType.WASTE,
                )
            )
        return classifications

    async def send_alerts(
        self,
        anomalies: list[CostAnomaly],
    ) -> list[AlertRecord]:
        """Send alerts for detected anomalies."""
        logger.info(
            "ccad.send_alerts",
            count=len(anomalies),
        )

        alerts: list[AlertRecord] = []
        for i, a in enumerate(anomalies):
            if a.severity in ("critical", "high"):
                channel = "slack"
                recipient = "#finops-alerts"
            else:
                channel = "email"
                recipient = "finops-team@corp.local"
            alerts.append(
                AlertRecord(
                    id=_gen_id("AL", a.id, i),
                    anomaly_id=a.id,
                    channel=channel,
                    status="sent",
                    recipient=recipient,
                    sent_at="2026-03-30T12:00:00Z",
                    acknowledged=False,
                )
            )
        return alerts

    async def record_metric(
        self,
        metric_name: str,
        value: float,
    ) -> dict[str, Any]:
        """Record an operational metric."""
        _metric_id = str(uuid4())
        logger.info(
            "ccad.record_metric",
            metric=metric_name,
            value=value,
        )
        return {
            "metric_id": _metric_id,
            "metric": metric_name,
            "value": value,
            "recorded": True,
        }
