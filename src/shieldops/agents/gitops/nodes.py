"""Node implementations for the GitOps Agent LangGraph workflow.

Each node is an async function that:
1. Queries external systems via the GitOpsToolkit
2. Updates the GitOps state with findings and results
3. Records its reasoning step in the audit trail
"""

from datetime import UTC, datetime
from typing import Any

import structlog
from pydantic import BaseModel, Field

from shieldops.agents.gitops.models import (
    GitOpsState,
    ReconciliationStage,
)
from shieldops.agents.gitops.tools import GitOpsToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

# Module-level toolkit reference, set by the runner at graph construction time.
_toolkit: GitOpsToolkit | None = None


def set_toolkit(toolkit: GitOpsToolkit) -> None:
    """Configure the toolkit used by all nodes. Called once at startup."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> GitOpsToolkit:
    if _toolkit is None:
        return GitOpsToolkit()  # Empty toolkit — safe for tests
    return _toolkit


class _LLMReconciliationAdvice(BaseModel):
    """LLM-generated advice for reconciliation planning."""

    risk_assessment: str = Field(description="Risk assessment of applying the reconciliation")
    recommended_order: list[str] = Field(
        description="Recommended order of resource IDs to reconcile"
    )
    requires_approval: bool = Field(description="Whether human approval should be required")
    confidence: float = Field(description="Confidence in the plan (0.0-1.0)", ge=0.0, le=1.0)
    reasoning: str = Field(description="Explanation of the planning decision")


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


async def detect_drift(state: GitOpsState) -> dict[str, Any]:
    """Detect drift between desired state (git) and actual infrastructure.

    Queries the Git repository for desired manifests and compares against
    live infrastructure state.
    """
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "gitops_detect_drift_start",
        request_id=state.request_id,
        repo_url=state.repo_url,
        branch=state.branch,
        namespace=state.namespace,
    )

    drift_items = await toolkit.detect_drift(
        repo_url=state.repo_url,
        branch=state.branch,
        namespace=state.namespace,
    )

    output_summary = f"Detected {len(drift_items)} drift items"
    if drift_items:
        severity_counts: dict[str, int] = {}
        for item in drift_items:
            severity_counts[item.severity] = severity_counts.get(item.severity, 0) + 1
        output_summary += f" — severity breakdown: {severity_counts}"

    step = {
        "step": "detect_drift",
        "input": f"repo={state.repo_url}, branch={state.branch}, ns={state.namespace}",
        "output": output_summary,
        "duration_ms": _elapsed_ms(start),
    }

    return {
        "drift_items": drift_items,
        "stage": ReconciliationStage.PLAN,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_drift",
        "started_at": start,
    }


async def plan_reconciliation(state: GitOpsState) -> dict[str, Any]:
    """Generate a reconciliation plan from detected drift items.

    Creates ordered actions with risk assessment and determines
    whether human approval is needed.
    """
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "gitops_plan_start",
        request_id=state.request_id,
        drift_count=len(state.drift_items),
    )

    plan = await toolkit.generate_reconciliation_plan(state.drift_items)

    # --- LLM enhancement: improve plan quality with AI reasoning ---
    llm_reasoning = ""
    try:
        drift_summary = "\n".join(
            f"- {d.resource_id} ({d.drift_type}): expected={d.expected_value}, "
            f"actual={d.actual_value}, severity={d.severity}"
            for d in state.drift_items
        )
        advice = await llm_structured(
            system_prompt=(
                "You are a GitOps reconciliation planner for Kubernetes infrastructure. "
                "Analyze the detected drift items and advise on reconciliation risk, "
                "ordering, and whether human approval is needed. Be conservative — "
                "flag anything that could cause downtime."
            ),
            user_prompt=(
                f"Repository: {state.repo_url} (branch: {state.branch})\n"
                f"Namespace: {state.namespace or 'all'}\n"
                f"Dry run: {state.dry_run}\n\n"
                f"Detected drift items:\n{drift_summary}\n\n"
                f"Toolkit plan: {len(plan.actions)} actions, "
                f"estimated_risk={plan.estimated_risk:.2f}, "
                f"requires_approval={plan.requires_approval}"
            ),
            schema=_LLMReconciliationAdvice,
        )
        if isinstance(advice, _LLMReconciliationAdvice):
            # Let LLM override approval requirement if it flags higher risk
            if advice.requires_approval and not plan.requires_approval:
                plan.requires_approval = True
            llm_reasoning = advice.reasoning
            logger.info(
                "llm_enhanced",
                agent="gitops",
                node="plan_reconciliation",
                llm_confidence=advice.confidence,
                llm_risk=advice.risk_assessment[:80],
            )
    except Exception:
        logger.debug("llm_fallback", agent="gitops", node="plan_reconciliation")

    output_summary = (
        f"Plan: {len(plan.actions)} actions, "
        f"risk={plan.estimated_risk:.2f}, "
        f"approval_required={plan.requires_approval}"
    )
    if llm_reasoning:
        output_summary += f" | LLM: {llm_reasoning[:120]}"

    # Calculate confidence based on drift clarity
    confidence = 1.0 - plan.estimated_risk if plan.items else 1.0

    step = {
        "step": "plan_reconciliation",
        "input": f"{len(state.drift_items)} drift items",
        "output": output_summary,
        "duration_ms": _elapsed_ms(start),
    }

    return {
        "plan": plan,
        "stage": ReconciliationStage.APPLY,
        "confidence_score": confidence,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "plan_reconciliation",
    }


async def apply_reconciliation(state: GitOpsState) -> dict[str, Any]:
    """Apply the reconciliation plan to infrastructure.

    Executes each action in the plan, respecting dry_run mode.
    """
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    if state.plan is None:
        logger.warning("gitops_apply_no_plan", request_id=state.request_id)
        return {
            "error": "No reconciliation plan available",
            "current_step": "apply_reconciliation",
        }

    logger.info(
        "gitops_apply_start",
        request_id=state.request_id,
        action_count=len(state.plan.actions),
        dry_run=state.dry_run,
    )

    results = await toolkit.apply_changes(
        plan=state.plan,
        dry_run=state.dry_run,
    )

    success_count = sum(1 for r in results if r.success)
    fail_count = len(results) - success_count

    output_summary = (
        f"Applied {len(results)} actions "
        f"(dry_run={state.dry_run}): "
        f"{success_count} succeeded, {fail_count} failed"
    )

    step = {
        "step": "apply_reconciliation",
        "input": f"{len(state.plan.actions)} planned actions, dry_run={state.dry_run}",
        "output": output_summary,
        "duration_ms": _elapsed_ms(start),
    }

    return {
        "apply_results": results,
        "stage": ReconciliationStage.VERIFY,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "apply_reconciliation",
    }


async def verify_and_report(state: GitOpsState) -> dict[str, Any]:
    """Verify reconciliation results and generate final report.

    Checks that all changes took effect and resources are healthy.
    Produces a summary of the entire reconciliation operation.
    """
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "gitops_verify_start",
        request_id=state.request_id,
        result_count=len(state.apply_results),
    )

    verification_passed = await toolkit.verify_deployment(state.apply_results)

    # Build change summary
    success_count = sum(1 for r in state.apply_results if r.success)
    total_count = len(state.apply_results)
    total_duration = sum(r.duration_seconds for r in state.apply_results)

    summary_lines = [
        f"GitOps Reconciliation {'Completed' if verification_passed else 'Failed'}",
        f"Repository: {state.repo_url} (branch: {state.branch})",
        f"Namespace: {state.namespace or 'all'}",
        f"Drift items detected: {len(state.drift_items)}",
        f"Actions applied: {success_count}/{total_count}",
        f"Total apply duration: {total_duration:.1f}s",
        f"Verification: {'PASSED' if verification_passed else 'FAILED'}",
        f"Dry run: {state.dry_run}",
    ]
    change_summary = "\n".join(summary_lines)

    # Calculate final duration
    duration_ms = 0
    if state.started_at:
        duration_ms = int((datetime.now(UTC) - state.started_at).total_seconds() * 1000)

    step = {
        "step": "verify_and_report",
        "input": f"{total_count} apply results",
        "output": f"verification={'passed' if verification_passed else 'failed'}",
        "duration_ms": _elapsed_ms(start),
    }

    return {
        "verification_passed": verification_passed,
        "change_summary": change_summary,
        "stage": ReconciliationStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
        "duration_ms": duration_ms,
    }
