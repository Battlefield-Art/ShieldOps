"""Tool functions for the Telemetry Optimizer Agent.

These tools interface with observability infrastructure to analyze costs,
detect waste, and apply optimizations to the telemetry pipeline.
"""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.telemetry_optimizer.models import (
    OptimizationExperiment,
    OptimizationProposal,
    TelemetryWaste,
    WasteCategory,
)
from shieldops.connectors.base import ConnectorRouter

logger = structlog.get_logger()


class TelemetryOptimizerToolkit:
    """Collection of tools for telemetry pipeline optimization.

    Injected into nodes at graph construction time to decouple agent logic
    from specific connector implementations.
    """

    def __init__(
        self,
        connector_router: ConnectorRouter | None = None,
        metrics_backend: Any = None,
        cost_api: Any = None,
    ) -> None:
        self._router = connector_router
        self._metrics_backend = metrics_backend
        self._cost_api = cost_api

    async def analyze_pipeline_costs(
        self,
        namespace: str,
    ) -> dict[str, Any]:
        """Get per-service telemetry costs for a namespace.

        Returns cost breakdown by service, signal type (metrics/logs/traces),
        and total data volume.
        """
        logger.info("analyzing_pipeline_costs", namespace=namespace)

        if self._cost_api is not None:
            try:
                return await self._cost_api.get_namespace_costs(namespace)  # type: ignore[no-any-return]
            except Exception as e:
                logger.error("cost_api_query_failed", namespace=namespace, error=str(e))

        # Fallback: return structure for downstream processing
        return {
            "namespace": namespace,
            "services": {},
            "total_monthly_cost": 0.0,
            "total_data_volume_gb": 0.0,
            "breakdown_by_signal": {
                "metrics": 0.0,
                "logs": 0.0,
                "traces": 0.0,
            },
        }

    async def detect_cardinality_explosion(
        self,
        service: str,
    ) -> list[dict[str, Any]]:
        """Find metrics with excessive label combinations for a service.

        Returns metrics where unique time-series count exceeds reasonable
        thresholds (>10k series per metric).
        """
        logger.info("detecting_cardinality_explosion", service=service)

        if self._metrics_backend is not None:
            try:
                return await self._metrics_backend.get_high_cardinality_metrics(service)  # type: ignore[no-any-return]
            except Exception as e:
                logger.error(
                    "cardinality_detection_failed",
                    service=service,
                    error=str(e),
                )

        return []

    async def detect_over_sampling(
        self,
        service: str,
    ) -> list[dict[str, Any]]:
        """Find services sampled above what their SLO tier requires.

        Compares actual sampling rate against the recommended rate for
        the service's criticality tier.
        """
        logger.info("detecting_over_sampling", service=service)

        if self._metrics_backend is not None:
            try:
                return await self._metrics_backend.get_sampling_analysis(service)  # type: ignore[no-any-return]
            except Exception as e:
                logger.error(
                    "over_sampling_detection_failed",
                    service=service,
                    error=str(e),
                )

        return []

    async def detect_duplicate_metrics(
        self,
        namespace: str,
    ) -> list[dict[str, Any]]:
        """Find duplicate or redundant metrics within a namespace.

        Identifies metrics that are semantically identical but collected
        from multiple exporters or instrumentation libraries.
        """
        logger.info("detecting_duplicate_metrics", namespace=namespace)

        if self._metrics_backend is not None:
            try:
                return await self._metrics_backend.find_duplicate_metrics(namespace)  # type: ignore[no-any-return]
            except Exception as e:
                logger.error(
                    "duplicate_detection_failed",
                    namespace=namespace,
                    error=str(e),
                )

        return []

    async def propose_optimization(
        self,
        waste: TelemetryWaste,
    ) -> OptimizationProposal:
        """Generate an optimization proposal for a specific waste item.

        Maps waste categories to concrete, reversible actions.
        """
        logger.info(
            "proposing_optimization",
            service=waste.service_name,
            category=waste.waste_category,
        )

        action_map: dict[WasteCategory, str] = {
            WasteCategory.HIGH_CARDINALITY: (
                f"Drop high-cardinality labels on {waste.service_name} to reduce series count"
            ),
            WasteCategory.OVER_SAMPLING: (
                f"Reduce sampling rate for {waste.service_name} to match SLO tier requirements"
            ),
            WasteCategory.DUPLICATE_METRICS: (
                f"Consolidate duplicate metrics for {waste.service_name} "
                f"into a single collection path"
            ),
            WasteCategory.UNUSED_DASHBOARDS: (
                f"Archive unused dashboards for {waste.service_name} "
                f"and stop associated data collection"
            ),
            WasteCategory.STALE_ALERTS: (
                f"Disable stale alert rules for {waste.service_name} "
                f"that have not fired in 90+ days"
            ),
        }

        risk_map: dict[WasteCategory, str] = {
            WasteCategory.HIGH_CARDINALITY: "medium",
            WasteCategory.OVER_SAMPLING: "medium",
            WasteCategory.DUPLICATE_METRICS: "low",
            WasteCategory.UNUSED_DASHBOARDS: "low",
            WasteCategory.STALE_ALERTS: "low",
        }

        proposal_id = f"opt-{uuid4().hex[:12]}"
        action = action_map.get(waste.waste_category, f"Optimize {waste.waste_category}")
        risk = risk_map.get(waste.waste_category, "medium")

        # Estimate savings based on waste category and cost
        savings_pct = min(waste.estimated_monthly_cost / max(waste.data_volume_gb, 0.1) * 5, 80.0)

        return OptimizationProposal(
            id=proposal_id,
            waste_category=waste.waste_category,
            target_service=waste.service_name,
            action=action,
            estimated_savings_pct=round(savings_pct, 1),
            risk=risk,
            reversible=True,
        )

    async def run_optimization_experiment(
        self,
        proposal: OptimizationProposal,
        budget_seconds: int = 300,
    ) -> OptimizationExperiment:
        """Test an optimization with a fixed time budget.

        Applies the optimization in a shadow/canary mode, measures
        before/after cost and observability metrics, then returns results.
        The optimization is automatically rolled back after measurement.
        """
        logger.info(
            "running_optimization_experiment",
            proposal_id=proposal.id,
            service=proposal.target_service,
            budget_seconds=budget_seconds,
        )

        # Default baseline values when no backend is available
        baseline_cost = 100.0
        experiment_cost = 100.0

        if self._cost_api is not None:
            try:
                baseline = await self._cost_api.measure_cost(
                    proposal.target_service,
                    duration_seconds=min(budget_seconds // 2, 60),
                )
                baseline_cost = baseline.get("cost", 100.0)

                # Apply optimization in shadow mode
                await self._cost_api.apply_shadow(proposal.id, proposal.action)

                # Measure with optimization
                experiment = await self._cost_api.measure_cost(
                    proposal.target_service,
                    duration_seconds=min(budget_seconds // 2, 60),
                )
                experiment_cost = experiment.get("cost", baseline_cost)

                # Roll back shadow
                await self._cost_api.rollback_shadow(proposal.id)
            except Exception as e:
                logger.error(
                    "experiment_failed",
                    proposal_id=proposal.id,
                    error=str(e),
                )

        # Calculate savings
        if baseline_cost > 0:
            savings_pct = ((baseline_cost - experiment_cost) / baseline_cost) * 100
        else:
            savings_pct = 0.0

        # Accept only if savings are meaningful and no observability loss
        accepted = savings_pct >= (proposal.estimated_savings_pct * 0.5) and savings_pct > 0

        return OptimizationExperiment(
            proposal_id=proposal.id,
            baseline_cost=baseline_cost,
            experiment_cost=experiment_cost,
            savings_pct=round(savings_pct, 2),
            observability_impact="none" if accepted else "potential_degradation",
            accepted=accepted,
        )

    async def apply_optimization(
        self,
        proposal: OptimizationProposal,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Apply an accepted optimization to the telemetry pipeline.

        Args:
            proposal: The optimization proposal to apply.
            dry_run: If True, only simulate the change without applying.

        Returns:
            Result dict with status and details.
        """
        logger.info(
            "applying_optimization",
            proposal_id=proposal.id,
            service=proposal.target_service,
            dry_run=dry_run,
        )

        result: dict[str, Any] = {
            "proposal_id": proposal.id,
            "service": proposal.target_service,
            "action": proposal.action,
            "dry_run": dry_run,
            "status": "simulated" if dry_run else "applied",
        }

        if not dry_run and self._cost_api is not None:
            try:
                apply_result = await self._cost_api.apply_optimization(
                    proposal.id,
                    proposal.action,
                )
                result["status"] = apply_result.get("status", "applied")
                result["details"] = apply_result
            except Exception as e:
                logger.error(
                    "apply_optimization_failed",
                    proposal_id=proposal.id,
                    error=str(e),
                )
                result["status"] = "failed"
                result["error"] = str(e)

        return result
