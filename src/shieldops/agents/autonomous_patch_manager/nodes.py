"""Node implementations for the Autonomous Patch Manager
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.autonomous_patch_manager.models import (
    APMStage,
    AutonomousPatchManagerState,
    ReasoningStep,
)
from shieldops.agents.autonomous_patch_manager.prompts import (
    SYSTEM_INVENTORY,
    SYSTEM_REPORT,
    SYSTEM_RISK,
    SYSTEM_SCHEDULE,
    DeploymentPlanOutput,
    InventoryScanOutput,
    PatchReportOutput,
    RiskAnalysisOutput,
)
from shieldops.agents.autonomous_patch_manager.tools import (
    AutonomousPatchManagerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AutonomousPatchManagerToolkit | None = None


def set_toolkit(
    toolkit: AutonomousPatchManagerToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> AutonomousPatchManagerToolkit:
    if _toolkit is None:
        return AutonomousPatchManagerToolkit()
    return _toolkit


def _step(
    chain: list[ReasoningStep],
    action: str,
    input_summary: str,
    output_summary: str,
    start: datetime,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Build a reasoning step with duration."""
    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return ReasoningStep(
        step_number=len(chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=elapsed,
        tool_used=tool_used,
    )


# ------------------------------------------------------------------
# Node: scan_inventory
# ------------------------------------------------------------------


async def scan_inventory(
    state: AutonomousPatchManagerState,
) -> dict[str, Any]:
    """Scan infrastructure assets to build patch
    inventory."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    inventory = await toolkit.scan_inventory(
        environments=state.target_environments,
        scope=state.scope,
    )

    inv_list: list[dict[str, Any]] = list(inventory)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "scan_name": state.scan_name,
                "environments": state.target_environments,
                "scope": state.scope,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_INVENTORY,
            user_prompt=f"Scan inventory for:\n{ctx}",
            schema=InventoryScanOutput,
        )
        if llm_out.assets:  # type: ignore[union-attr]
            inv_list = [
                *inv_list,
                *llm_out.assets,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="scan_inventory",
            count=len(llm_out.assets),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="scan_inventory",
        )

    step = _step(
        state.reasoning_chain,
        "scan_inventory",
        f"Environments: {len(state.target_environments)}",
        f"Scanned {len(inv_list)} assets",
        start,
        "asset_scanner",
    )

    return {
        "inventory": inv_list,
        "total_assets": len(inv_list),
        "stage": APMStage.SCAN_INVENTORY,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "scan_inventory",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: check_patches
# ------------------------------------------------------------------


async def check_patches(
    state: AutonomousPatchManagerState,
) -> dict[str, Any]:
    """Check for available patches against the current
    asset inventory."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    patches = await toolkit.check_available_patches(
        inventory=state.inventory,
    )

    step = _step(
        state.reasoning_chain,
        "check_patches",
        f"Checking patches for {len(state.inventory)} assets",
        f"Found {len(patches)} available patches",
        start,
        "patch_checker",
    )

    return {
        "available_patches": patches,
        "patches_available": len(patches),
        "stage": APMStage.CHECK_PATCHES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "check_patches",
    }


# ------------------------------------------------------------------
# Node: assess_risk
# ------------------------------------------------------------------


async def assess_risk(
    state: AutonomousPatchManagerState,
) -> dict[str, Any]:
    """Assess risk of deploying each available patch."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments = await toolkit.assess_patch_risk(
        patches=state.available_patches,
        inventory=state.inventory,
    )

    risk_list: list[dict[str, Any]] = list(assessments)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "patch_count": len(state.available_patches),
                "patches_sample": state.available_patches[:5],
                "asset_count": state.total_assets,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_RISK,
            user_prompt=f"Assess patch risk:\n{ctx}",
            schema=RiskAnalysisOutput,
        )
        if llm_out.high_risk_patches:  # type: ignore[union-attr]
            rand_id = random.randint(1000, 9999)  # noqa: S311
            risk_list.append(
                {
                    "assessment_id": f"llm-{rand_id}",
                    "risk_score": llm_out.risk_score,  # type: ignore[union-attr]
                    "high_risk": llm_out.high_risk_patches,  # type: ignore[union-attr]
                    "safe": llm_out.safe_patches,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="assess_risk",
            high_risk=len(llm_out.high_risk_patches),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_risk",
        )

    step = _step(
        state.reasoning_chain,
        "assess_risk",
        f"Assessing {len(state.available_patches)} patches",
        f"Produced {len(risk_list)} risk assessments",
        start,
        "risk_assessor",
    )

    return {
        "risk_assessments": risk_list,
        "stage": APMStage.ASSESS_RISK,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_risk",
    }


# ------------------------------------------------------------------
# Node: schedule_deployment
# ------------------------------------------------------------------


async def schedule_deployment(
    state: AutonomousPatchManagerState,
) -> dict[str, Any]:
    """Schedule patch deployments based on risk
    assessments."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    schedules = await toolkit.schedule_deployment(
        risk_assessments=state.risk_assessments,
        strategy=state.strategy.value,
        auto_deploy=state.auto_deploy,
    )

    sched_list: list[dict[str, Any]] = list(schedules)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "risk_count": len(state.risk_assessments),
                "strategy": state.strategy.value,
                "auto_deploy": state.auto_deploy,
                "environments": state.target_environments,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_SCHEDULE,
            user_prompt=f"Plan deployment:\n{ctx}",
            schema=DeploymentPlanOutput,
        )
        if llm_out.schedule:  # type: ignore[union-attr]
            sched_list = [
                *sched_list,
                *llm_out.schedule,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="schedule_deployment",
            schedules=len(llm_out.schedule),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="schedule_deployment",
        )

    step = _step(
        state.reasoning_chain,
        "schedule_deployment",
        f"Scheduling {len(state.risk_assessments)} assessments",
        f"Created {len(sched_list)} deployment schedules",
        start,
        "deployment_scheduler",
    )

    return {
        "schedules": sched_list,
        "stage": APMStage.SCHEDULE_DEPLOYMENT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "schedule_deployment",
    }


# ------------------------------------------------------------------
# Node: deploy_patches
# ------------------------------------------------------------------


async def deploy_patches(
    state: AutonomousPatchManagerState,
) -> dict[str, Any]:
    """Execute patch deployments according to schedule."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    deployments = await toolkit.deploy_patches(
        schedules=state.schedules,
    )

    deployed = len(deployments)
    succeeded = sum(1 for d in deployments if d.get("success"))
    rate = (succeeded / max(deployed, 1)) * 100

    step = _step(
        state.reasoning_chain,
        "deploy_patches",
        f"Deploying {len(state.schedules)} schedules",
        f"Deployed {deployed} patches, {rate:.0f}% success",
        start,
        "patch_deployer",
    )

    return {
        "deployments": deployments,
        "patches_deployed": deployed,
        "deployment_success_rate": rate,
        "stage": APMStage.DEPLOY,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "deploy_patches",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: AutonomousPatchManagerState,
) -> dict[str, Any]:
    """Generate the final patch management cycle report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report = await toolkit.generate_report(
        inventory=state.inventory,
        patches=state.available_patches,
        deployments=state.deployments,
        success_rate=state.deployment_success_rate,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "scan_name": state.scan_name,
                "total_assets": state.total_assets,
                "patches_available": state.patches_available,
                "patches_deployed": state.patches_deployed,
                "success_rate": state.deployment_success_rate,
                "strategy": state.strategy.value,
                "deployments_sample": state.deployments[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate patch report:\n{ctx}",
            schema=PatchReportOutput,
        )
        if isinstance(llm_out, PatchReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "patches_applied": llm_out.patches_applied,
                    "recommendations": llm_out.recommendations,
                    "compliance_impact": llm_out.compliance_impact,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                recommendations=len(llm_out.recommendations),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    # Record metrics
    await toolkit.record_metric(
        "patch_success_rate",
        state.deployment_success_rate,
        {"scan": state.scan_name},
    )

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.patches_deployed} deployments",
        f"Report generated, success={state.deployment_success_rate:.0f}%",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": APMStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
