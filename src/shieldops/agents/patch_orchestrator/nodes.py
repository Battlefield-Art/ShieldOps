"""Node implementations for the Patch Orchestrator Agent."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.patch_orchestrator.models import (
    PatchOrchestratorState,
    PatchStage,
    ReasoningStep,
)
from shieldops.agents.patch_orchestrator.prompts import (
    SYSTEM_PRIORITIZE,
    SYSTEM_REPORT,
    PatchPrioritizationResult,
    PatchReportResult,
)
from shieldops.agents.patch_orchestrator.tools import (
    PatchOrchestratorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: PatchOrchestratorToolkit | None = None


def set_toolkit(tk: PatchOrchestratorToolkit) -> None:
    """Set module-level toolkit for all nodes."""
    global _toolkit
    _toolkit = tk


def _get_toolkit() -> PatchOrchestratorToolkit:
    if _toolkit is None:
        return PatchOrchestratorToolkit()
    return _toolkit


async def inventory_systems(
    state: PatchOrchestratorState,
) -> dict[str, Any]:
    """Discover systems in the target environment."""
    start = datetime.now(UTC)
    tk = _get_toolkit()

    systems = await tk.inventory_systems(state.target_environment)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="inventory_systems",
        input_summary=f"env={state.target_environment}",
        output_summary=f"Found {len(systems)} systems",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="cmdb",
    )
    return {
        "systems_inventoried": systems,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": PatchStage.INVENTORY_SYSTEMS,
    }


async def assess_patches(
    state: PatchOrchestratorState,
) -> dict[str, Any]:
    """Assess available patches for inventoried systems."""
    start = datetime.now(UTC)
    tk = _get_toolkit()

    patches = await tk.assess_patches(state.systems_inventoried)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="assess_patches",
        input_summary=(f"{len(state.systems_inventoried)} systems"),
        output_summary=f"Assessed {len(patches)} patches",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="patch_db",
    )
    return {
        "patches_assessed": patches,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": PatchStage.ASSESS_PATCHES,
    }


async def prioritize_deployment(
    state: PatchOrchestratorState,
) -> dict[str, Any]:
    """Prioritize patches and create deployment plan."""
    start = datetime.now(UTC)
    tk = _get_toolkit()

    plan = await tk.create_deployment_plan(
        state.systems_inventoried,
        state.patches_assessed,
    )

    # LLM-enhanced prioritization
    patch_lines = [
        f"- {p.patch_name} (CVE: {p.cve_id}, "
        f"severity: {p.severity}, "
        f"affected: {len(p.affected_systems)}, "
        f"risk: {p.risk_score})"
        for p in state.patches_assessed
    ]
    user_prompt = "Patches:\n" + "\n".join(patch_lines)
    rationale = "Default priority order by severity."

    try:
        result = cast(
            PatchPrioritizationResult,
            await llm_structured(
                system_prompt=SYSTEM_PRIORITIZE,
                user_prompt=user_prompt,
                schema=PatchPrioritizationResult,
            ),
        )
        rationale = result.rationale
    except Exception as e:
        logger.error("llm_prioritize_failed", error=str(e))

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="prioritize_deployment",
        input_summary=(f"{len(state.patches_assessed)} patches"),
        output_summary=rationale[:200],
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )
    return {
        "deployment_plan": plan,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": PatchStage.PRIORITIZE_DEPLOYMENT,
    }


async def deploy_patches(
    state: PatchOrchestratorState,
) -> dict[str, Any]:
    """Deploy patches using canary-then-rollout strategy."""
    start = datetime.now(UTC)
    tk = _get_toolkit()

    if state.deployment_plan is None:
        return {
            "error": "No deployment plan.",
            "current_stage": PatchStage.DEPLOY_PATCHES,
        }

    deployments = []
    plan = state.deployment_plan

    # Canary phase
    for sys_id in plan.canary_targets:
        for patch in state.patches_assessed:
            if sys_id in patch.affected_systems:
                dep = await tk.deploy_patch(
                    sys_id,
                    patch.id,
                    is_canary=True,
                )
                deployments.append(dep)

    # Rollout phase (only if canary succeeded)
    canary_ok = all(d.status == "success" for d in deployments if d.is_canary)
    if canary_ok:
        for sys_id in plan.rollout_targets:
            for patch in state.patches_assessed:
                if sys_id in patch.affected_systems:
                    dep = await tk.deploy_patch(
                        sys_id,
                        patch.id,
                    )
                    deployments.append(dep)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="deploy_patches",
        input_summary=f"canary={len(plan.canary_targets)}, rollout={len(plan.rollout_targets)}",
        output_summary=(f"Deployed {len(deployments)} patches, canary_ok={canary_ok}"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="deployment_engine",
    )
    return {
        "deployments": deployments,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": PatchStage.DEPLOY_PATCHES,
    }


async def verify_success(
    state: PatchOrchestratorState,
) -> dict[str, Any]:
    """Verify deployments and rollback failures."""
    start = datetime.now(UTC)
    tk = _get_toolkit()

    verifications = []
    patched = 0
    failed = 0
    rolled_back = 0

    for dep in state.deployments:
        ver = await tk.verify_deployment(dep)
        verifications.append(ver)
        if ver.patch_applied and ver.service_healthy:
            patched += 1
        elif ver.rollback_needed:
            await tk.rollback_deployment(dep)
            rolled_back += 1
        else:
            failed += 1

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="verify_success",
        input_summary=(f"{len(state.deployments)} deployments"),
        output_summary=(f"patched={patched}, failed={failed}, rolled_back={rolled_back}"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="health_check",
    )
    return {
        "verifications": verifications,
        "patched_count": patched,
        "failed_count": failed,
        "rollback_count": rolled_back,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": PatchStage.VERIFY_SUCCESS,
    }


async def generate_report(
    state: PatchOrchestratorState,
) -> dict[str, Any]:
    """Generate final patch deployment report."""
    start = datetime.now(UTC)

    ctx = (
        f"Patched: {state.patched_count}, "
        f"Failed: {state.failed_count}, "
        f"Rolled back: {state.rollback_count}\n"
        f"Systems: {len(state.systems_inventoried)}\n"
        f"Patches: {len(state.patches_assessed)}"
    )

    report = (
        f"Patch deployment complete. "
        f"{state.patched_count} patched, "
        f"{state.failed_count} failed, "
        f"{state.rollback_count} rolled back."
    )

    try:
        result = cast(
            PatchReportResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=ctx,
                schema=PatchReportResult,
            ),
        )
        report = f"{result.title}\n\n{result.executive_summary}\nRisk: {result.risk_assessment}"
    except Exception as e:
        logger.error("llm_report_failed", error=str(e))

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary=ctx[:100],
        output_summary=report[:200],
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )

    total = sum(s.duration_ms for s in [*state.reasoning_chain, step])
    return {
        "report_summary": report,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": PatchStage.REPORT,
        "duration_ms": total,
    }
