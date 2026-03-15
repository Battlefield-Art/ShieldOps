"""Node implementations for the Telemetry Optimizer Agent LangGraph workflow.

Each node is an async function that:
1. Queries telemetry infrastructure via the TelemetryOptimizerToolkit
2. Uses the LLM to analyze costs, waste, and optimization opportunities
3. Updates the optimizer state with findings
4. Records its reasoning step in the audit trail
"""

from datetime import UTC, datetime
from typing import Any, cast

import structlog
from pydantic import BaseModel, Field

from shieldops.agents.telemetry_optimizer.models import (
    OptimizationExperiment,
    OptimizationProposal,
    OptimizationStage,
    ReasoningStep,
    TelemetryOptimizerState,
    TelemetryWaste,
    WasteCategory,
)
from shieldops.agents.telemetry_optimizer.prompts import SYSTEM_PROPOSE
from shieldops.agents.telemetry_optimizer.tools import TelemetryOptimizerToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()


class _ProposalLLMResult(BaseModel):
    """Structured LLM output for optimization proposals."""

    summary: str = Field(description="Brief summary of proposed optimizations")
    priority_order: list[str] = Field(
        description="Recommended priority order for applying optimizations"
    )
    risk_warnings: list[str] = Field(description="Risk warnings about proposed changes")
    estimated_total_savings_pct: float = Field(
        description="Estimated total savings percentage across all proposals"
    )


# Module-level toolkit reference, set by the runner at graph construction time.
_toolkit: TelemetryOptimizerToolkit | None = None


def set_toolkit(toolkit: TelemetryOptimizerToolkit) -> None:
    """Configure the toolkit used by all nodes. Called once at startup."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> TelemetryOptimizerToolkit:
    if _toolkit is None:
        return TelemetryOptimizerToolkit()  # Empty toolkit — safe for tests
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


async def analyze_pipeline(state: TelemetryOptimizerState) -> dict[str, Any]:
    """Analyze per-service telemetry pipeline costs for the target namespace."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()
    namespace = state.target_namespace

    logger.info(
        "telemetry_optimizer_analyzing_pipeline",
        request_id=state.request_id,
        namespace=namespace,
    )

    pipeline_costs = await toolkit.analyze_pipeline_costs(namespace)

    total_cost = pipeline_costs.get("total_monthly_cost", 0.0)
    service_count = len(pipeline_costs.get("services", {}))
    total_volume = pipeline_costs.get("total_data_volume_gb", 0.0)

    output_summary = (
        f"Namespace '{namespace}': ${total_cost:.2f}/mo across "
        f"{service_count} services, {total_volume:.1f} GB total volume"
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="analyze_pipeline",
        input_summary=f"Analyzing telemetry costs for namespace: {namespace}",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="cost_api",
    )

    return {
        "pipeline_costs": pipeline_costs,
        "stage": OptimizationStage.IDENTIFY_WASTE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_pipeline",
    }


async def identify_waste(state: TelemetryOptimizerState) -> dict[str, Any]:
    """Identify telemetry waste: cardinality explosions, over-sampling, duplicates."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()
    namespace = state.target_namespace

    logger.info(
        "telemetry_optimizer_identifying_waste",
        request_id=state.request_id,
        namespace=namespace,
    )

    waste_items: list[TelemetryWaste] = []
    services = list(state.pipeline_costs.get("services", {}).keys())

    # If no services from cost analysis, use namespace as a single service
    if not services:
        services = [namespace] if namespace else []

    for service in services:
        # Detect cardinality explosions
        cardinality_issues = await toolkit.detect_cardinality_explosion(service)
        for issue in cardinality_issues:
            waste_items.append(
                TelemetryWaste(
                    service_name=service,
                    waste_category=WasteCategory.HIGH_CARDINALITY,
                    estimated_monthly_cost=issue.get("estimated_cost", 0.0),
                    data_volume_gb=issue.get("data_volume_gb", 0.0),
                    description=(
                        f"Metric '{issue.get('metric', 'unknown')}' has "
                        f"{issue.get('series_count', 0)} unique series"
                    ),
                )
            )

        # Detect over-sampling
        sampling_issues = await toolkit.detect_over_sampling(service)
        for issue in sampling_issues:
            waste_items.append(
                TelemetryWaste(
                    service_name=service,
                    waste_category=WasteCategory.OVER_SAMPLING,
                    estimated_monthly_cost=issue.get("estimated_cost", 0.0),
                    data_volume_gb=issue.get("data_volume_gb", 0.0),
                    description=(
                        f"Service sampled at {issue.get('actual_rate', '?')} "
                        f"but SLO tier requires {issue.get('recommended_rate', '?')}"
                    ),
                )
            )

    # Detect duplicate metrics (namespace-wide)
    if namespace:
        duplicate_issues = await toolkit.detect_duplicate_metrics(namespace)
        for issue in duplicate_issues:
            waste_items.append(
                TelemetryWaste(
                    service_name=issue.get("service", namespace),
                    waste_category=WasteCategory.DUPLICATE_METRICS,
                    estimated_monthly_cost=issue.get("estimated_cost", 0.0),
                    data_volume_gb=issue.get("data_volume_gb", 0.0),
                    description=(
                        f"Duplicate metrics: {issue.get('metrics', [])} "
                        f"from {issue.get('sources', [])}"
                    ),
                )
            )

    output_summary = (
        f"Found {len(waste_items)} waste items across {len(services)} services. "
        f"Categories: {', '.join(set(w.waste_category for w in waste_items)) or 'none'}"
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="identify_waste",
        input_summary=f"Scanning {len(services)} services for telemetry waste",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="metrics_backend",
    )

    return {
        "waste_items": waste_items,
        "stage": OptimizationStage.PROPOSE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "identify_waste",
    }


async def propose_optimizations(state: TelemetryOptimizerState) -> dict[str, Any]:
    """Generate optimization proposals for each identified waste item."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "telemetry_optimizer_proposing",
        request_id=state.request_id,
        waste_count=len(state.waste_items),
    )

    proposals: list[OptimizationProposal] = []

    for waste in state.waste_items:
        proposal = await toolkit.propose_optimization(waste)
        proposals.append(proposal)

    # Sort by estimated savings (highest first)
    proposals.sort(key=lambda p: p.estimated_savings_pct, reverse=True)

    output_summary = (
        f"Generated {len(proposals)} proposals. "
        f"Top savings: {proposals[0].estimated_savings_pct:.1f}% "
        f"({proposals[0].action[:80]})"
        if proposals
        else "No proposals generated — no waste identified"
    )

    # LLM enhancement: richer optimization reasoning
    try:
        import json

        waste_context = json.dumps(
            [
                {
                    "service": w.service_name,
                    "category": w.waste_category,
                    "cost": w.estimated_monthly_cost,
                    "description": w.description,
                }
                for w in state.waste_items
            ],
            default=str,
        )
        proposal_context = json.dumps(
            [
                {
                    "action": p.action[:100],
                    "target": p.target_service,
                    "savings_pct": p.estimated_savings_pct,
                    "risk": p.risk_level if hasattr(p, "risk_level") else "unknown",
                }
                for p in proposals
            ],
            default=str,
        )
        llm_result = cast(
            _ProposalLLMResult,
            await llm_structured(
                system_prompt=SYSTEM_PROPOSE,
                user_prompt=(
                    f"Waste items:\n{waste_context}\n\nGenerated proposals:\n{proposal_context}"
                ),
                schema=_ProposalLLMResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            node="propose_optimizations",
            estimated_total_savings=llm_result.estimated_total_savings_pct,
            risk_warnings=len(llm_result.risk_warnings),
        )
        output_summary = (
            f"{llm_result.summary} "
            f"Estimated total savings: {llm_result.estimated_total_savings_pct:.1f}%."
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="propose_optimizations")

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="propose_optimizations",
        input_summary=f"Generating proposals for {len(state.waste_items)} waste items",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="propose_optimization",
    )

    return {
        "proposals": proposals,
        "stage": OptimizationStage.EXPERIMENT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "propose_optimizations",
    }


async def run_experiments(state: TelemetryOptimizerState) -> dict[str, Any]:
    """Run optimization experiments for each proposal and accept/reject."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "telemetry_optimizer_experimenting",
        request_id=state.request_id,
        proposal_count=len(state.proposals),
        budget_seconds=state.budget_seconds,
    )

    experiments: list[OptimizationExperiment] = []
    # Divide budget across proposals
    per_proposal_budget = max(
        state.budget_seconds // max(len(state.proposals), 1),
        30,
    )

    for proposal in state.proposals:
        experiment = await toolkit.run_optimization_experiment(
            proposal=proposal,
            budget_seconds=per_proposal_budget,
        )
        experiments.append(experiment)

    accepted_count = sum(1 for e in experiments if e.accepted)
    total_savings = 0.0
    if experiments:
        accepted_experiments = [e for e in experiments if e.accepted]
        if accepted_experiments:
            total_savings = sum(e.savings_pct for e in accepted_experiments) / len(
                accepted_experiments
            )

    confidence = min(accepted_count / max(len(experiments), 1), 1.0)

    output_summary = (
        f"Ran {len(experiments)} experiments: {accepted_count} accepted, "
        f"{len(experiments) - accepted_count} rejected. "
        f"Average savings: {total_savings:.1f}%"
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="run_experiments",
        input_summary=(
            f"Testing {len(state.proposals)} proposals with {per_proposal_budget}s budget each"
        ),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="run_optimization_experiment",
    )

    return {
        "experiments": experiments,
        "total_savings_pct": round(total_savings, 2),
        "confidence_score": round(confidence, 2),
        "stage": OptimizationStage.APPLY,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "run_experiments",
    }
