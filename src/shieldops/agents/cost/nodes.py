"""Node implementations for the Cost Agent LangGraph workflow.

Each node is an async function that:
1. Gathers or analyzes cost data via the CostToolkit
2. Uses the LLM to assess and prioritize findings
3. Updates the cost analysis state with results
4. Records its reasoning step in the audit trail
"""

from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

import structlog

from shieldops.agents.cost.models import (
    CostAnalysisState,
    CostAnomaly,
    CostSavings,
    CostStep,
    OptimizationRecommendation,
    ResourceCost,
)
from shieldops.agents.cost.prompts import (
    SYSTEM_COST_ANOMALY_ASSESSMENT,
    SYSTEM_COST_FORECAST,
    SYSTEM_OPTIMIZATION_ASSESSMENT,
    CostAnomalyAssessmentResult,
    CostForecastResult,
    OptimizationAssessmentResult,
)
from shieldops.agents.cost.tools import CostToolkit
from shieldops.policy.engine import PolicyContext
from shieldops.policy.engine import evaluate as policy_evaluate
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

# Module-level toolkit reference, set by the runner at graph construction time.
_toolkit: CostToolkit | None = None


def set_toolkit(toolkit: CostToolkit | None) -> None:
    """Configure the toolkit used by all nodes. Called once at startup."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> CostToolkit:
    if _toolkit is None:
        return CostToolkit()
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


async def gather_costs(state: CostAnalysisState) -> dict[str, Any]:
    """Gather resource inventory and billing data."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "cost_gathering_data",
        analysis_id=state.analysis_id,
        environment=state.target_environment.value,
    )

    # Get billing data
    billing = await toolkit.query_billing(
        environment=state.target_environment,
        period=state.period,
    )

    # Build resource cost models
    resource_costs: list[ResourceCost] = []
    for raw in billing.get("resource_costs", []):
        resource_costs.append(
            ResourceCost(
                resource_id=raw.get("resource_id", "unknown"),
                resource_type=raw.get("resource_type", "unknown"),
                service=raw.get("service", "unknown"),
                environment=state.target_environment,
                provider=raw.get("provider", "unknown"),
                daily_cost=raw.get("daily_cost", 0),
                monthly_cost=raw.get("monthly_cost", 0),
                usage_percent=raw.get("usage_percent", 0),
            )
        )

    by_service = billing.get("by_service", {"unknown": 0})
    top_service = max(by_service, key=by_service.get)

    step = CostStep(
        step_number=1,
        action="gather_costs",
        input_summary=(
            f"Gathering billing data for {state.target_environment.value} ({state.period})"
        ),
        output_summary=(
            f"Total: ${billing['total_monthly']:.0f}/mo across "
            f"{len(resource_costs)} resources. "
            f"Top service: {top_service}"
        ),
        duration_ms=_elapsed_ms(start),
        tool_used="billing_api",
    )

    return {
        "analysis_start": start,
        "resource_costs": resource_costs,
        "total_daily_spend": billing.get("total_daily", 0),
        "total_monthly_spend": billing.get("total_monthly", 0),
        "spend_by_service": billing.get("by_service", {}),
        "spend_by_environment": billing.get("by_environment", {}),
        "reasoning_chain": [step],
        "current_step": "gather_costs",
    }


async def detect_anomalies(state: CostAnalysisState) -> dict[str, Any]:
    """Detect cost anomalies across resources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "cost_detecting_anomalies",
        analysis_id=state.analysis_id,
        resource_count=len(state.resource_costs),
    )

    # Convert resource costs to dicts for anomaly detection
    rc_dicts = [
        {
            "resource_id": rc.resource_id,
            "service": rc.service,
            "daily_cost": rc.daily_cost,
            "monthly_cost": rc.monthly_cost,
            "usage_percent": rc.usage_percent,
        }
        for rc in state.resource_costs
    ]

    anomaly_data = await toolkit.detect_anomalies(rc_dicts)

    anomalies: list[CostAnomaly] = []
    for raw in anomaly_data.get("anomalies", []):
        anomalies.append(
            CostAnomaly(
                resource_id=raw.get("resource_id", "unknown"),
                service=raw.get("service", "unknown"),
                anomaly_type=raw.get("anomaly_type", "unknown"),
                severity=raw.get("severity", "medium"),
                expected_daily_cost=raw.get("expected_daily_cost", 0),
                actual_daily_cost=raw.get("actual_daily_cost", 0),
                deviation_percent=raw.get("deviation_percent", 0),
                started_at=raw.get("started_at"),
                description=raw.get("description", ""),
            )
        )

    output_summary = (
        f"Found {anomaly_data['total_anomalies']} anomalies, "
        f"{anomaly_data['critical_count']} critical"
    )

    # LLM assessment of anomalies
    if anomalies:
        context_lines = [
            "## Cost Anomaly Report",
            f"Total anomalies: {len(anomalies)}",
            f"Critical: {anomaly_data['critical_count']}",
            "",
            "## Anomaly Details",
        ]
        for a in anomalies[:20]:
            context_lines.append(
                f"- {a.resource_id} ({a.anomaly_type}, {a.severity}): "
                f"${a.actual_daily_cost:.2f}/day vs ${a.expected_daily_cost:.2f}/day expected "
                f"(+{a.deviation_percent:.1f}%)"
            )

        try:
            assessment = cast(
                CostAnomalyAssessmentResult,
                await llm_structured(
                    system_prompt=SYSTEM_COST_ANOMALY_ASSESSMENT,
                    user_prompt="\n".join(context_lines),
                    schema=CostAnomalyAssessmentResult,
                ),
            )
            output_summary = (
                f"{assessment.summary}. "
                f"Critical: {len(assessment.critical_anomalies)}, "
                f"Root causes: {len(assessment.root_causes)}"
            )
        except Exception as e:
            logger.error("llm_cost_anomaly_assessment_failed", error=str(e))

    step = CostStep(
        step_number=len(state.reasoning_chain) + 1,
        action="detect_anomalies",
        input_summary=f"Analyzing {len(state.resource_costs)} resources for cost anomalies",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="anomaly_detector + llm",
    )

    return {
        "cost_anomalies": anomalies,
        "critical_anomaly_count": anomaly_data["critical_count"],
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_anomalies",
    }


async def _evaluate_cost_action(
    rec: OptimizationRecommendation,
    environment: str,
) -> dict[str, Any]:
    """Evaluate a cost-modifying recommendation against OPA policy.

    Categories that modify infrastructure (terminate, resize) require
    policy approval. Read-only categories pass through automatically.
    """
    cost_modifying_categories = {"rightsizing", "unused_resources", "scheduling", "terminate"}
    if rec.category not in cost_modifying_categories:
        return {"resource_id": rec.resource_id, "allowed": True, "decision": "skipped"}

    risk_score = 1.0 - rec.confidence  # lower confidence => higher risk
    try:
        context = PolicyContext(
            agent_name="cost",
            action_type=f"cost_{rec.category}",
            target_resources=[rec.resource_id],
            environment=environment,
            risk_score=risk_score,
            metadata={
                "monthly_savings": rec.monthly_savings,
                "effort": rec.effort,
                "category": rec.category,
            },
        )
        decision = await policy_evaluate(
            action=f"Cost optimization: {rec.category} on {rec.resource_id}",
            context=context,
        )
        return {
            "resource_id": rec.resource_id,
            "category": rec.category,
            "allowed": decision.allowed,
            "decision": decision.decision.value,
            "reason": decision.reason,
        }
    except Exception as e:
        logger.warning(
            "cost_policy_evaluation_failed",
            resource_id=rec.resource_id,
            error=str(e),
        )
        return {
            "resource_id": rec.resource_id,
            "allowed": False,
            "decision": "error",
            "reason": str(e),
        }


async def recommend_optimizations(state: CostAnalysisState) -> dict[str, Any]:
    """Identify and prioritize cost optimization opportunities.

    Uses rule-based detection augmented with LLM-powered FinOps recommendations.
    All cost-modifying recommendations are evaluated against OPA policy before
    being included in the final output.
    """
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "cost_recommending_optimizations",
        analysis_id=state.analysis_id,
        resource_count=len(state.resource_costs),
    )

    rc_dicts = [
        {
            "resource_id": rc.resource_id,
            "service": rc.service,
            "daily_cost": rc.daily_cost,
            "monthly_cost": rc.monthly_cost,
            "usage_percent": rc.usage_percent,
        }
        for rc in state.resource_costs
    ]

    # 1. Rule-based optimization scan
    opt_data = await toolkit.get_optimization_opportunities(rc_dicts)

    recommendations: list[OptimizationRecommendation] = []
    seen_resource_ids: set[str] = set()
    for raw in opt_data.get("recommendations", []):
        rid = raw.get("resource_id", "unknown")
        seen_resource_ids.add(rid)
        recommendations.append(
            OptimizationRecommendation(
                id=f"opt-{uuid4().hex[:8]}",
                category=raw.get("category", "general"),
                resource_id=rid,
                service=raw.get("service", "unknown"),
                current_monthly_cost=raw.get("current_monthly_cost", 0),
                projected_monthly_cost=raw.get("projected_monthly_cost", 0),
                monthly_savings=raw.get("monthly_savings", 0),
                confidence=raw.get("confidence", 0.5),
                effort=raw.get("effort", "medium"),
                description=raw.get("description", ""),
                implementation_steps=raw.get("implementation_steps", []),
            )
        )

    # 2. LLM-powered FinOps recommendations (augment rule-based)
    billing_summary = {
        "total_monthly": state.total_monthly_spend,
        "total_daily": state.total_daily_spend,
        "by_service": state.spend_by_service,
        "resource_costs": rc_dicts,
    }
    llm_recs = await toolkit.generate_recommendations(billing_summary)
    for raw in llm_recs:
        rid = raw.get("resource_id", "unknown")
        if rid not in seen_resource_ids:
            seen_resource_ids.add(rid)
            recommendations.append(
                OptimizationRecommendation(
                    id=f"opt-{uuid4().hex[:8]}",
                    category=raw.get("category", "general"),
                    resource_id=rid,
                    service=raw.get("service", "unknown"),
                    current_monthly_cost=raw.get("current_monthly_cost", 0),
                    projected_monthly_cost=raw.get("projected_monthly_cost", 0),
                    monthly_savings=raw.get("monthly_savings", 0),
                    confidence=raw.get("confidence", 0.5),
                    effort=raw.get("effort", "medium"),
                    description=raw.get("description", ""),
                    implementation_steps=raw.get("implementation_steps", []),
                )
            )

    total_savings = sum(r.monthly_savings for r in recommendations)
    output_summary = (
        f"{len(recommendations)} optimizations identified, "
        f"${total_savings:.0f}/mo potential savings"
    )

    # 3. OPA policy check for cost-modifying recommendations
    policy_decisions: list[dict[str, Any]] = []
    env_str = state.target_environment.value if state.target_environment else "dev"
    for rec in recommendations:
        decision = await _evaluate_cost_action(rec, env_str)
        policy_decisions.append(decision)

    # 4. LLM assessment of the full recommendation set
    if recommendations:
        context_lines = [
            "## Optimization Opportunities",
            f"Total recommendations: {len(recommendations)}",
            f"Total potential savings: ${total_savings:.2f}/mo",
            "",
            "## Recommendations",
        ]
        for rec in recommendations[:20]:
            context_lines.append(
                f"- {rec.category}: {rec.resource_id} — "
                f"save ${rec.monthly_savings:.0f}/mo ({rec.effort} effort). "
                f"{rec.description}"
            )

        try:
            assessment = cast(
                OptimizationAssessmentResult,
                await llm_structured(
                    system_prompt=SYSTEM_OPTIMIZATION_ASSESSMENT,
                    user_prompt="\n".join(context_lines),
                    schema=OptimizationAssessmentResult,
                ),
            )
            output_summary = (
                f"{assessment.summary}. "
                f"Quick wins: {len(assessment.quick_wins)}, "
                f"Est. savings: ${assessment.estimated_total_monthly_savings:.0f}/mo"
            )
        except Exception as e:
            logger.error("llm_optimization_assessment_failed", error=str(e))

    step = CostStep(
        step_number=len(state.reasoning_chain) + 1,
        action="recommend_optimizations",
        input_summary=f"Analyzing {len(state.resource_costs)} resources for optimization",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="optimizer + llm + opa",
    )

    return {
        "optimization_recommendations": recommendations,
        "total_potential_savings": total_savings,
        "policy_decisions": policy_decisions,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "recommend_optimizations",
    }


async def synthesize_savings(state: CostAnalysisState) -> dict[str, Any]:
    """Synthesize all findings into a cost savings summary and forecast."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info("cost_synthesizing_savings", analysis_id=state.analysis_id)

    # Get automation savings data
    automation_data = await toolkit.get_automation_savings(period=state.period)

    savings = CostSavings(
        period=state.period,
        total_monthly_spend=state.total_monthly_spend,
        optimized_monthly_spend=state.total_monthly_spend - state.total_potential_savings,
        total_potential_savings=state.total_potential_savings,
        savings_by_category={},
        hours_saved_by_automation=automation_data.get("total_hours_saved", 0),
        automation_savings_usd=automation_data.get("automation_savings_usd", 0),
        engineer_hourly_rate=automation_data.get("engineer_hourly_rate", 75.0),
    )

    # Aggregate savings by category
    for rec in state.optimization_recommendations:
        cat = rec.category
        savings.savings_by_category[cat] = (
            savings.savings_by_category.get(cat, 0) + rec.monthly_savings
        )

    # Build context for LLM synthesis
    context_lines = [
        "## Cost Analysis Summary",
        f"Monthly spend: ${state.total_monthly_spend:.0f}",
        f"Daily spend: ${state.total_daily_spend:.2f}",
        "",
        "## Spend by Service",
    ]
    for svc, cost in state.spend_by_service.items():
        context_lines.append(f"- {svc}: ${cost:.0f}/mo")

    context_lines.extend(
        [
            "",
            "## Anomalies",
            f"Total anomalies: {len(state.cost_anomalies)}",
            f"Critical: {state.critical_anomaly_count}",
            "",
            "## Optimizations",
            f"Recommendations: {len(state.optimization_recommendations)}",
            f"Potential savings: ${state.total_potential_savings:.0f}/mo",
            "",
            "## Automation Savings",
            f"Hours saved: {savings.hours_saved_by_automation:.0f}",
            f"Automation savings: ${savings.automation_savings_usd:.0f}",
            "",
            "## Investigation Chain",
        ]
    )
    for step in state.reasoning_chain:
        context_lines.append(f"Step {step.step_number} ({step.action}): {step.output_summary}")

    # Default health score
    health_score = 100.0
    if state.critical_anomaly_count > 0:
        health_score -= min(30, state.critical_anomaly_count * 15)
    if state.total_potential_savings > 0 and state.total_monthly_spend > 0:
        waste_ratio = state.total_potential_savings / state.total_monthly_spend
        health_score -= min(40, waste_ratio * 100)
    health_score = max(0, min(100, health_score))

    output_summary = f"Cost health score: {health_score:.1f}/100"

    try:
        assessment = cast(
            CostForecastResult,
            await llm_structured(
                system_prompt=SYSTEM_COST_FORECAST,
                user_prompt="\n".join(context_lines),
                schema=CostForecastResult,
            ),
        )
        health_score = assessment.overall_health_score
        output_summary = (
            f"Score: {assessment.overall_health_score:.1f}/100. {assessment.summary[:200]}"
        )
    except Exception as e:
        logger.error("llm_cost_forecast_failed", error=str(e))

    step = CostStep(
        step_number=len(state.reasoning_chain) + 1,
        action="synthesize_savings",
        input_summary="Synthesizing cost analysis and savings forecast",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="llm",
    )

    return {
        "cost_savings": savings,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
        "analysis_duration_ms": int(
            (datetime.now(UTC) - state.analysis_start).total_seconds() * 1000
        )
        if state.analysis_start
        else 0,
    }
