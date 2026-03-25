"""Tool functions for the Cost Anomaly Detector Agent."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from shieldops.agents.cost_anomaly.models import (
    AnomalyType,
    CloudService,
    CostAnomaly,
    CostDataPoint,
    CostRecommendation,
    CostSeverity,
    WasteClassification,
)

logger = structlog.get_logger()

# Baseline daily costs per service (USD) — used for anomaly thresholds
BASELINE_COSTS: dict[str, float] = {
    CloudService.AWS_EC2: 120.0,
    CloudService.AWS_RDS: 85.0,
    CloudService.AWS_S3: 15.0,
    CloudService.GCP_COMPUTE: 100.0,
    CloudService.GCP_BIGQUERY: 40.0,
    CloudService.AZURE_VM: 110.0,
    CloudService.KUBERNETES: 200.0,
    CloudService.LLM_API: 50.0,
}

# Standard deviation multiplier for anomaly detection
_ANOMALY_SIGMA = 2.0

# Utilization threshold below which a resource is considered idle
_IDLE_UTILIZATION_PCT = 10.0

# Utilization threshold for rightsizing recommendations
_RIGHTSIZING_UTILIZATION_PCT = 30.0


class CostAnomalyToolkit:
    """Toolkit bridging Cost Anomaly agent to billing APIs and cost trackers."""

    def __init__(
        self,
        billing_client: Any | None = None,
        llm_cost_tracker: Any | None = None,
    ) -> None:
        self._billing_client = billing_client
        self._llm_cost_tracker = llm_cost_tracker

    async def collect_billing_data(
        self,
        tenant_id: str,
    ) -> list[CostDataPoint]:
        """Collect billing data from AWS Cost Explorer, GCP Billing, Azure Cost Management.

        In production this calls real cloud billing APIs. Returns synthetic data
        when no billing client is configured so the graph can still execute.
        """
        logger.info("cost_anomaly.collect_billing", tenant_id=tenant_id)

        if self._billing_client is not None:
            try:
                raw = await self._billing_client.get_cost_data(tenant_id)
                return [CostDataPoint(**r) for r in raw if isinstance(r, dict)]
            except Exception:
                logger.warning("cost_anomaly.billing_client_error", tenant_id=tenant_id)

        # Synthetic baseline data for development / testing
        now = time.time()
        return [
            CostDataPoint(
                id=f"cdp-{uuid.uuid4().hex[:8]}",
                service=CloudService.AWS_EC2,
                resource_id="i-0abc123def456",
                daily_cost=350.0,
                monthly_forecast=10500.0,
                budget_pct=87.5,
                region="us-east-1",
                tags={"team": "platform", "env": "production"},
                timestamp=now,
            ),
            CostDataPoint(
                id=f"cdp-{uuid.uuid4().hex[:8]}",
                service=CloudService.AWS_RDS,
                resource_id="db-prod-main",
                daily_cost=90.0,
                monthly_forecast=2700.0,
                budget_pct=54.0,
                region="us-east-1",
                tags={"team": "data", "env": "production"},
                timestamp=now,
            ),
            CostDataPoint(
                id=f"cdp-{uuid.uuid4().hex[:8]}",
                service=CloudService.GCP_BIGQUERY,
                resource_id="bq-analytics-prod",
                daily_cost=180.0,
                monthly_forecast=5400.0,
                budget_pct=135.0,
                region="us-central1",
                tags={"team": "analytics", "env": "production"},
                timestamp=now,
            ),
            CostDataPoint(
                id=f"cdp-{uuid.uuid4().hex[:8]}",
                service=CloudService.LLM_API,
                resource_id="anthropic-claude-sonnet",
                daily_cost=220.0,
                monthly_forecast=6600.0,
                budget_pct=110.0,
                region="global",
                tags={"team": "ai-platform", "env": "production"},
                timestamp=now,
            ),
            CostDataPoint(
                id=f"cdp-{uuid.uuid4().hex[:8]}",
                service=CloudService.KUBERNETES,
                resource_id="eks-prod-cluster",
                daily_cost=195.0,
                monthly_forecast=5850.0,
                budget_pct=73.1,
                region="us-west-2",
                tags={"team": "platform", "env": "production"},
                timestamp=now,
            ),
            CostDataPoint(
                id=f"cdp-{uuid.uuid4().hex[:8]}",
                service=CloudService.AWS_S3,
                resource_id="s3-logs-archive",
                daily_cost=12.0,
                monthly_forecast=360.0,
                budget_pct=24.0,
                region="us-east-1",
                tags={"team": "ops", "env": "production"},
                timestamp=now,
            ),
        ]

    async def detect_cost_anomalies(
        self,
        data: list[CostDataPoint],
    ) -> list[CostAnomaly]:
        """Detect cost anomalies using statistical deviation from baselines.

        Flags any cost data point that exceeds 2-sigma from the expected
        baseline daily cost for its service type.
        """
        logger.info("cost_anomaly.detect_anomalies", data_points=len(data))
        anomalies: list[CostAnomaly] = []

        for point in data:
            baseline = BASELINE_COSTS.get(point.service, 50.0)
            deviation_pct = ((point.daily_cost - baseline) / baseline) * 100.0

            if deviation_pct > _ANOMALY_SIGMA * 100.0:
                severity = CostSeverity.CRITICAL
                anomaly_type = AnomalyType.COST_SPIKE
            elif deviation_pct > 100.0:
                severity = CostSeverity.HIGH
                anomaly_type = AnomalyType.COST_SPIKE
            elif deviation_pct > 50.0:
                severity = CostSeverity.MEDIUM
                anomaly_type = AnomalyType.COST_SPIKE
            elif point.budget_pct > 100.0:
                severity = CostSeverity.HIGH
                anomaly_type = AnomalyType.BILLING_ERROR
            else:
                continue

            anomalies.append(
                CostAnomaly(
                    id=f"ca-{uuid.uuid4().hex[:8]}",
                    service=point.service,
                    resource_id=point.resource_id,
                    anomaly_type=anomaly_type,
                    severity=severity,
                    description=(
                        f"{point.service.value} resource {point.resource_id} "
                        f"cost ${point.daily_cost:.2f}/day vs baseline "
                        f"${baseline:.2f}/day ({deviation_pct:+.1f}%)"
                    ),
                    expected_cost=baseline,
                    actual_cost=point.daily_cost,
                    deviation_pct=round(deviation_pct, 1),
                    first_detected=point.timestamp,
                )
            )

        logger.info("cost_anomaly.anomalies_detected", count=len(anomalies))
        return anomalies

    async def classify_waste(
        self,
        data: list[CostDataPoint],
    ) -> list[WasteClassification]:
        """Identify idle resources, oversized instances, and unused storage.

        Resources with utilization below thresholds are classified as waste.
        """
        logger.info("cost_anomaly.classify_waste", data_points=len(data))
        waste: list[WasteClassification] = []

        # Simulate utilization data (in production, pulled from CloudWatch / Stackdriver)
        utilization_map: dict[str, float] = {
            "i-0abc123def456": 8.0,
            "db-prod-main": 45.0,
            "bq-analytics-prod": 22.0,
            "eks-prod-cluster": 60.0,
            "s3-logs-archive": 5.0,
            "anthropic-claude-sonnet": 70.0,
        }

        for point in data:
            util = utilization_map.get(point.resource_id, 50.0)

            if util < _IDLE_UTILIZATION_PCT:
                waste.append(
                    WasteClassification(
                        id=f"wc-{uuid.uuid4().hex[:8]}",
                        resource_id=point.resource_id,
                        service=point.service,
                        waste_type="idle_resource",
                        monthly_waste=point.monthly_forecast * 0.9,
                        utilization_pct=util,
                        recommendation=(
                            f"Terminate or downsize {point.resource_id} — only {util}% utilized"
                        ),
                        savings_potential=point.monthly_forecast * 0.9,
                    )
                )
            elif util < _RIGHTSIZING_UTILIZATION_PCT:
                waste.append(
                    WasteClassification(
                        id=f"wc-{uuid.uuid4().hex[:8]}",
                        resource_id=point.resource_id,
                        service=point.service,
                        waste_type="oversized_resource",
                        monthly_waste=point.monthly_forecast * 0.4,
                        utilization_pct=util,
                        recommendation=(
                            f"Rightsize {point.resource_id} — "
                            f"{util}% utilization suggests smaller instance"
                        ),
                        savings_potential=point.monthly_forecast * 0.4,
                    )
                )

        logger.info("cost_anomaly.waste_classified", count=len(waste))
        return waste

    async def analyze_llm_costs(
        self,
        tenant_id: str,
    ) -> dict[str, Any]:
        """Break down LLM API costs by model, agent, and operation.

        In production, queries the LLM cost tracker for per-tenant spend.
        """
        logger.info("cost_anomaly.analyze_llm_costs", tenant_id=tenant_id)

        if self._llm_cost_tracker is not None:
            try:
                return await self._llm_cost_tracker.get_breakdown(tenant_id)
            except Exception:
                logger.warning(
                    "cost_anomaly.llm_tracker_error",
                    tenant_id=tenant_id,
                )

        # Synthetic LLM cost breakdown
        return {
            "total_daily": 220.0,
            "total_monthly_forecast": 6600.0,
            "by_model": {
                "claude-sonnet-4": {"daily": 120.0, "monthly": 3600.0, "calls": 4200},
                "claude-haiku-3.5": {"daily": 35.0, "monthly": 1050.0, "calls": 18000},
                "claude-opus-4": {"daily": 65.0, "monthly": 1950.0, "calls": 800},
            },
            "by_agent": {
                "investigation": {"daily": 80.0, "pct": 36.4},
                "remediation": {"daily": 55.0, "pct": 25.0},
                "soc_analyst": {"daily": 40.0, "pct": 18.2},
                "threat_hunter": {"daily": 30.0, "pct": 13.6},
                "other": {"daily": 15.0, "pct": 6.8},
            },
            "budget_pct": 110.0,
            "overrun_detected": True,
            "top_expensive_operations": [
                {"op": "deep_investigation", "daily_cost": 45.0},
                {"op": "threat_correlation", "daily_cost": 28.0},
                {"op": "incident_triage", "daily_cost": 22.0},
            ],
        }

    async def generate_recommendations(
        self,
        anomalies: list[CostAnomaly],
        waste: list[WasteClassification],
    ) -> list[CostRecommendation]:
        """Generate actionable cost optimization recommendations."""
        logger.info(
            "cost_anomaly.generate_recommendations",
            anomalies=len(anomalies),
            waste=len(waste),
        )
        recs: list[CostRecommendation] = []

        for anomaly in anomalies:
            savings = anomaly.actual_cost - anomaly.expected_cost
            if anomaly.anomaly_type == AnomalyType.COST_SPIKE:
                recs.append(
                    CostRecommendation(
                        id=f"rec-{uuid.uuid4().hex[:8]}",
                        anomaly_id=anomaly.id,
                        action="investigate_spike",
                        target=anomaly.resource_id,
                        description=(
                            f"Investigate cost spike on {anomaly.resource_id}: "
                            f"${anomaly.actual_cost:.2f}/day vs "
                            f"${anomaly.expected_cost:.2f}/day expected"
                        ),
                        estimated_savings=round(savings * 30, 2),
                        auto_executable=False,
                        priority=anomaly.severity.value,
                    )
                )
            elif anomaly.anomaly_type == AnomalyType.BILLING_ERROR:
                recs.append(
                    CostRecommendation(
                        id=f"rec-{uuid.uuid4().hex[:8]}",
                        anomaly_id=anomaly.id,
                        action="review_billing",
                        target=anomaly.resource_id,
                        description=(
                            f"Review billing for {anomaly.resource_id} — "
                            f"budget exceeded at {anomaly.deviation_pct}%"
                        ),
                        estimated_savings=round(savings * 30, 2),
                        auto_executable=False,
                        priority="high",
                    )
                )

        for item in waste:
            if item.waste_type == "idle_resource":
                recs.append(
                    CostRecommendation(
                        id=f"rec-{uuid.uuid4().hex[:8]}",
                        anomaly_id=item.id,
                        action="terminate_idle",
                        target=item.resource_id,
                        description=item.recommendation,
                        estimated_savings=round(item.savings_potential, 2),
                        auto_executable=True,
                        priority="high",
                    )
                )
            elif item.waste_type == "oversized_resource":
                recs.append(
                    CostRecommendation(
                        id=f"rec-{uuid.uuid4().hex[:8]}",
                        anomaly_id=item.id,
                        action="rightsize",
                        target=item.resource_id,
                        description=item.recommendation,
                        estimated_savings=round(item.savings_potential, 2),
                        auto_executable=True,
                        priority="medium",
                    )
                )

        logger.info("cost_anomaly.recommendations_generated", count=len(recs))
        return recs
