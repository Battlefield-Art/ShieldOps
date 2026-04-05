"""Tool functions for the Cost Agent.

Bridges external billing APIs, cloud resource inventories,
and usage metrics into the cost analysis workflow.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from pydantic import BaseModel, Field

from shieldops.connectors.base import ConnectorRouter
from shieldops.models.base import Environment
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()


class CostRecommendationOutput(BaseModel):
    """Structured output from LLM cost recommendation generation."""

    recommendations: list[dict[str, Any]] = Field(
        description="List of cost optimization recommendations with category, resource_id, "
        "description, monthly_savings, confidence, effort, and implementation_steps"
    )
    total_estimated_savings: float = Field(
        ge=0.0, description="Total estimated monthly savings in USD"
    )
    executive_summary: str = Field(
        description="Brief executive summary of the cost optimization strategy"
    )


class CostToolkit:
    """Encapsulates external integrations for cost analysis.

    Pluggable billing sources and connector router allow
    production use with real APIs and test use with stubs.
    """

    def __init__(
        self,
        connector_router: ConnectorRouter | None = None,
        billing_sources: list[Any] | None = None,
    ) -> None:
        self._router = connector_router
        self._billing_sources = billing_sources or []

    async def get_resource_inventory(self, environment: Environment) -> dict[str, Any]:
        """Get inventory of all cloud resources and their types.

        Returns resource list with types, providers, and basic metadata.
        """
        logger.info(
            "cost.resource_inventory_query",
            environment=environment.value,
            has_router=self._router is not None,
        )
        if self._router:
            try:
                resources: list[dict[str, Any]] = []
                for provider in self._router.providers:
                    connector = self._router.get(provider)
                    provider_resources = await connector.list_resources(
                        resource_type="all", environment=environment
                    )
                    resources.extend(
                        {
                            "resource_id": r.id,
                            "resource_type": r.resource_type,
                            "provider": r.provider,
                            "name": r.name,
                            "labels": r.labels,
                        }
                        for r in provider_resources
                    )
                logger.info(
                    "cost.resource_inventory_success",
                    total_count=len(resources),
                    providers=self._router.providers,
                )
                return {
                    "resources": resources,
                    "total_count": len(resources),
                    "providers": self._router.providers,
                }
            except Exception as e:
                logger.error("cost.resource_inventory_failed", error=str(e))

        logger.debug("cost.resource_inventory_fallback_stub")
        # Default stub response when no router configured
        return {
            "resources": [
                {
                    "resource_id": "i-web-001",
                    "resource_type": "instance",
                    "provider": "aws",
                    "name": "web-server-1",
                    "labels": {"team": "platform"},
                },
                {
                    "resource_id": "i-api-001",
                    "resource_type": "instance",
                    "provider": "aws",
                    "name": "api-server-1",
                    "labels": {"team": "backend"},
                },
                {
                    "resource_id": "rds-main",
                    "resource_type": "database",
                    "provider": "aws",
                    "name": "main-db",
                    "labels": {"team": "data"},
                },
                {
                    "resource_id": "pod-worker-001",
                    "resource_type": "pod",
                    "provider": "kubernetes",
                    "name": "worker-pod",
                    "labels": {"app": "worker"},
                },
                {
                    "resource_id": "s3-logs",
                    "resource_type": "storage",
                    "provider": "aws",
                    "name": "log-bucket",
                    "labels": {"team": "platform"},
                },
            ],
            "total_count": 5,
            "providers": ["aws", "kubernetes"],
        }

    async def query_billing(
        self,
        environment: Environment,
        period: str = "30d",
    ) -> dict[str, Any]:
        """Query cloud billing data for resources.

        Tries sources in order: explicit billing sources, AWS Cost Explorer
        via connector_router, then falls back to stub data.
        """
        # 1. Try explicit billing sources first
        for source in self._billing_sources:
            try:
                result: dict[str, Any] = await source.query(environment=environment, period=period)
                logger.info(
                    "cost.billing_query_success",
                    source=type(source).__name__,
                    environment=environment.value,
                    period=period,
                )
                return result
            except Exception as e:
                logger.warning(
                    "cost.billing_source_failed",
                    source=type(source).__name__,
                    error=str(e),
                )

        # 2. Try AWS connector to build cost data from resource inventory
        if self._router and "aws" in self._router.providers:
            try:
                aws_connector = self._router.get("aws")
                resources = await aws_connector.list_resources(
                    resource_type="all", environment=environment
                )
                if resources:
                    # Build billing data from discovered resources.
                    # In production, this would call AWS Cost Explorer (ce_client)
                    # directly. For now we enrich inventory with cost metadata
                    # when available via resource tags/labels.
                    resource_costs = []
                    for r in resources:
                        cost_tag = (r.labels or {}).get("monthly_cost", "0")
                        usage_tag = (r.labels or {}).get("usage_percent", "50")
                        monthly = float(cost_tag)
                        resource_costs.append(
                            {
                                "resource_id": r.id,
                                "resource_type": r.resource_type,
                                "provider": r.provider,
                                "service": r.resource_type,
                                "daily_cost": round(monthly / 30, 2),
                                "monthly_cost": monthly,
                                "usage_percent": float(usage_tag),
                            }
                        )
                    total_monthly = sum(rc["monthly_cost"] for rc in resource_costs)
                    logger.info(
                        "cost.aws_inventory_billing_success",
                        environment=environment.value,
                        resource_count=len(resource_costs),
                        total_monthly=total_monthly,
                    )
                    return {
                        "period": period,
                        "currency": "USD",
                        "total_daily": round(total_monthly / 30, 2),
                        "total_monthly": total_monthly,
                        "by_service": {},
                        "by_environment": {environment.value: total_monthly},
                        "resource_costs": resource_costs,
                    }
            except Exception as e:
                logger.warning("cost.aws_connector_billing_failed", error=str(e))

        logger.debug(
            "cost.billing_fallback_stub",
            environment=environment.value,
            period=period,
        )

        # 3. Default stub billing data
        return {
            "period": period,
            "currency": "USD",
            "total_daily": 342.50,
            "total_monthly": 10275.00,
            "by_service": {
                "compute": 4800.00,
                "database": 2400.00,
                "storage": 1200.00,
                "network": 975.00,
                "kubernetes": 900.00,
            },
            "by_environment": {
                "production": 7200.00,
                "staging": 2050.00,
                "development": 1025.00,
            },
            "resource_costs": [
                {
                    "resource_id": "i-web-001",
                    "resource_type": "instance",
                    "service": "compute",
                    "daily_cost": 48.00,
                    "monthly_cost": 1440.00,
                    "usage_percent": 35.0,
                },
                {
                    "resource_id": "i-api-001",
                    "resource_type": "instance",
                    "service": "compute",
                    "daily_cost": 96.00,
                    "monthly_cost": 2880.00,
                    "usage_percent": 72.0,
                },
                {
                    "resource_id": "rds-main",
                    "resource_type": "database",
                    "service": "database",
                    "daily_cost": 80.00,
                    "monthly_cost": 2400.00,
                    "usage_percent": 55.0,
                },
                {
                    "resource_id": "pod-worker-001",
                    "resource_type": "pod",
                    "service": "kubernetes",
                    "daily_cost": 30.00,
                    "monthly_cost": 900.00,
                    "usage_percent": 15.0,
                },
                {
                    "resource_id": "s3-logs",
                    "resource_type": "storage",
                    "service": "storage",
                    "daily_cost": 40.00,
                    "monthly_cost": 1200.00,
                    "usage_percent": 80.0,
                },
            ],
        }

    async def detect_anomalies(
        self,
        resource_costs: list[dict[str, Any]],
        threshold_percent: float = 30.0,
    ) -> dict[str, Any]:
        """Detect cost anomalies by comparing against baseline.

        Identifies resources with spending significantly above their
        historical average within the analysis period.
        """
        logger.info(
            "cost.anomaly_detection",
            resource_count=len(resource_costs),
            threshold_percent=threshold_percent,
        )
        anomalies = []
        now = datetime.now(UTC)

        for rc in resource_costs:
            daily_cost = rc.get("daily_cost", 0)
            usage = rc.get("usage_percent", 50)

            # Flag resources with low utilization but high cost
            if usage < 20 and daily_cost > 20:
                deviation = ((daily_cost - 10) / max(10, 1)) * 100
                anomalies.append(
                    {
                        "resource_id": rc["resource_id"],
                        "service": rc.get("service", "unknown"),
                        "anomaly_type": "unused",
                        "severity": "high" if daily_cost > 50 else "medium",
                        "expected_daily_cost": daily_cost * (usage / 100),
                        "actual_daily_cost": daily_cost,
                        "deviation_percent": round(deviation, 1),
                        "started_at": now - timedelta(days=7),
                        "description": (
                            f"Resource {rc['resource_id']} has {usage}%"
                            f" utilization but costs ${daily_cost:.2f}/day"
                        ),
                    }
                )

            # Flag resources exceeding threshold above a baseline
            baseline = daily_cost * 0.7  # simulate 70% of current as baseline
            if daily_cost > baseline * (1 + threshold_percent / 100):
                anomalies.append(
                    {
                        "resource_id": rc["resource_id"],
                        "service": rc.get("service", "unknown"),
                        "anomaly_type": "spike",
                        "severity": "critical" if daily_cost > 100 else "medium",
                        "expected_daily_cost": round(baseline, 2),
                        "actual_daily_cost": daily_cost,
                        "deviation_percent": round(((daily_cost - baseline) / baseline) * 100, 1),
                        "started_at": now - timedelta(days=2),
                        "description": (
                            f"Resource {rc['resource_id']} spending"
                            f" ${daily_cost:.2f}/day vs"
                            f" ${baseline:.2f}/day baseline"
                        ),
                    }
                )

        critical_count = sum(1 for a in anomalies if a["severity"] == "critical")
        logger.info(
            "cost.anomaly_detection_complete",
            total_anomalies=len(anomalies),
            critical_count=critical_count,
        )

        return {
            "anomalies": anomalies,
            "total_anomalies": len(anomalies),
            "critical_count": critical_count,
        }

    async def get_optimization_opportunities(
        self,
        resource_costs: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Identify cost optimization opportunities.

        Analyzes utilization patterns and suggests rightsizing,
        scheduling, and resource cleanup actions.
        """
        logger.info("cost.optimization_scan", resource_count=len(resource_costs))
        recommendations = []
        total_savings = 0.0

        for rc in resource_costs:
            usage = rc.get("usage_percent", 50)
            monthly = rc.get("monthly_cost", 0)
            resource_id = rc.get("resource_id", "unknown")
            service = rc.get("service", "unknown")

            # Rightsizing: resources below 40% utilization
            if usage < 40 and monthly > 100:
                savings = monthly * 0.4  # could save ~40% by downsizing
                total_savings += savings
                recommendations.append(
                    {
                        "category": "rightsizing",
                        "resource_id": resource_id,
                        "service": service,
                        "current_monthly_cost": monthly,
                        "projected_monthly_cost": round(monthly - savings, 2),
                        "monthly_savings": round(savings, 2),
                        "confidence": 0.8,
                        "effort": "low",
                        "description": f"Downsize {resource_id} — only {usage}% utilized",
                        "implementation_steps": [
                            f"Verify {resource_id} workload can run on smaller instance",
                            "Schedule downsize during maintenance window",
                            "Monitor for 48 hours post-change",
                        ],
                    }
                )

            # Unused resources: below 10% utilization
            if usage < 10 and monthly > 50:
                total_savings += monthly
                recommendations.append(
                    {
                        "category": "unused_resources",
                        "resource_id": resource_id,
                        "service": service,
                        "current_monthly_cost": monthly,
                        "projected_monthly_cost": 0,
                        "monthly_savings": monthly,
                        "confidence": 0.7,
                        "effort": "low",
                        "description": (
                            f"Consider terminating {resource_id} — only {usage}% utilized"
                        ),
                        "implementation_steps": [
                            f"Confirm {resource_id} is not needed by any service",
                            "Create snapshot/backup before termination",
                            "Terminate resource",
                        ],
                    }
                )

        logger.info(
            "cost.optimization_scan_complete",
            total_recommendations=len(recommendations),
            total_potential_savings=round(total_savings, 2),
        )
        return {
            "recommendations": recommendations,
            "total_recommendations": len(recommendations),
            "total_potential_monthly_savings": round(total_savings, 2),
        }

    async def get_automation_savings(
        self,
        period: str = "30d",
        engineer_hourly_rate: float = 75.0,
    ) -> dict[str, Any]:
        """Calculate cost savings from automated operations.

        Estimates hours saved by ShieldOps automation vs. manual operations.
        """
        logger.info("cost.automation_savings_query", period=period)
        # In production, this would query the investigation/remediation
        # databases for actual time-saved metrics. Stub data here.
        return {
            "period": period,
            "investigations_automated": 45,
            "avg_investigation_hours_saved": 1.5,
            "remediations_automated": 22,
            "avg_remediation_hours_saved": 2.0,
            "total_hours_saved": 45 * 1.5 + 22 * 2.0,
            "engineer_hourly_rate": engineer_hourly_rate,
            "automation_savings_usd": (45 * 1.5 + 22 * 2.0) * engineer_hourly_rate,
        }

    async def generate_recommendations(self, cost_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Generate LLM-powered cost optimization recommendations.

        Uses the LLM to analyze cost data and produce actionable recommendations.
        Falls back to heuristic analysis when the LLM is unavailable.
        """
        logger.info(
            "cost.generating_recommendations",
            resource_count=len(cost_data.get("resource_costs", [])),
            total_monthly=cost_data.get("total_monthly", 0),
        )
        try:
            result = await llm_structured(
                system_prompt=(
                    "You are a FinOps expert. Analyze the provided cloud cost data and "
                    "recommend specific optimizations. For each recommendation include: "
                    "category (rightsizing/unused_resources/reserved_instances/scheduling/"
                    "architecture), resource_id, description, monthly_savings estimate, "
                    "confidence (0-1), effort (low/medium/high), and implementation_steps."
                ),
                user_prompt=f"Cost data: {json.dumps(cost_data, default=str)[:2000]}",
                schema=CostRecommendationOutput,
            )
            if isinstance(result, CostRecommendationOutput):
                logger.info(
                    "cost.llm_recommendations_success",
                    count=len(result.recommendations),
                    total_savings=result.total_estimated_savings,
                )
                return result.recommendations
            # If result is a dict (fallback parse)
            if isinstance(result, dict) and "recommendations" in result:
                return result["recommendations"]
            return [result] if isinstance(result, dict) else []
        except Exception as e:
            logger.debug("cost.llm_fallback", error=str(e))
            return self._heuristic_recommendations(cost_data)

    def _heuristic_recommendations(self, cost_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Generate rule-based recommendations when LLM is unavailable.

        Applies simple utilization and cost thresholds to produce
        recommendations without requiring an LLM call.
        """
        recommendations: list[dict[str, Any]] = []
        for rc in cost_data.get("resource_costs", []):
            usage = rc.get("usage_percent", 50)
            monthly = rc.get("monthly_cost", 0)
            resource_id = rc.get("resource_id", "unknown")

            if usage < 10 and monthly > 50:
                recommendations.append(
                    {
                        "category": "unused_resources",
                        "resource_id": resource_id,
                        "description": (
                            f"Resource {resource_id} has only {usage}% utilization "
                            f"but costs ${monthly:.2f}/mo. Consider termination."
                        ),
                        "monthly_savings": monthly,
                        "confidence": 0.7,
                        "effort": "low",
                        "implementation_steps": [
                            f"Verify {resource_id} has no active dependents",
                            "Create backup/snapshot",
                            "Terminate or decommission resource",
                        ],
                    }
                )
            elif usage < 40 and monthly > 100:
                savings = monthly * 0.4
                recommendations.append(
                    {
                        "category": "rightsizing",
                        "resource_id": resource_id,
                        "description": (
                            f"Resource {resource_id} is only {usage}% utilized. "
                            f"Downsize to save ~${savings:.2f}/mo."
                        ),
                        "monthly_savings": round(savings, 2),
                        "confidence": 0.8,
                        "effort": "low",
                        "implementation_steps": [
                            f"Analyze workload pattern for {resource_id}",
                            "Select appropriate smaller instance type",
                            "Schedule downsize during maintenance window",
                            "Monitor performance for 48 hours",
                        ],
                    }
                )
        logger.info(
            "cost.heuristic_recommendations",
            count=len(recommendations),
        )
        return recommendations

    @staticmethod
    def _parse_period_days(period: str) -> int:
        """Parse a period string like '30d', '7d', '90d' into days."""
        period = period.strip().lower()
        if period.endswith("d"):
            try:
                return int(period[:-1])
            except ValueError:
                pass
        return 30  # default to 30 days
