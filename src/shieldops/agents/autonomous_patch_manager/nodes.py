"""Node implementations for the Autonomous Patch Manager Agent."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.autonomous_patch_manager.models import (
    APMStage,
    AutonomousPatchManagerState,
    ReasoningStep,
)
from shieldops.agents.autonomous_patch_manager.prompts import (
    SYSTEM_ASSESS_PATCHES,
    SYSTEM_EXECUTE,
    SYSTEM_SCAN_INVENTORY,
    SYSTEM_SCHEDULE,
    SYSTEM_VALIDATE,
    ExecutionOutput,
    InventoryScanOutput,
    PatchAssessmentOutput,
    ScheduleOutput,
    ValidationOutput,
)
from shieldops.agents.autonomous_patch_manager.tools import (
    AutonomousPatchManagerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AutonomousPatchManagerToolkit | None = None


def _get_toolkit() -> AutonomousPatchManagerToolkit:
    if _toolkit is None:
        return AutonomousPatchManagerToolkit()
    return _toolkit


def _step(
    state: AutonomousPatchManagerState,
    action: str,
    input_summary: str,
    output_summary: str,
    duration_ms: int,
    tool_used: str | None = None,
) -> ReasoningStep:
    return ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=duration_ms,
        tool_used=tool_used,
    )


async def scan_inventory(
    state: AutonomousPatchManagerState,
) -> dict[str, Any]:
    """Scan asset inventory for patch status."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    inventory = await toolkit.scan_inventory(state.config)

    try:
        ctx = _json.dumps({"asset_count": len(inventory)}, default=str)
        llm_result = await llm_structured(
            system_prompt=SYSTEM_SCAN_INVENTORY,
            user_prompt=f"Inventory scan context:\n{ctx}",
            schema=InventoryScanOutput,
        )
        if hasattr(llm_result, "total_assets"):
            logger.info("llm_enhanced", node="scan_inventory")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="scan_inventory")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "scan_inventory",
        f"config={list(state.config.keys())}",
        f"found {len(inventory)} assets",
        elapsed,
        "asset_scanner",
    )
    await toolkit.record_metric("assets_scanned", float(len(inventory)))

    return {
        "inventory": inventory,
        "stage": APMStage.ASSESS_PATCHES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "scan_inventory",
        "session_start": start,
    }


async def assess_patches(
    state: AutonomousPatchManagerState,
) -> dict[str, Any]:
    """Assess available patches for the inventory."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments = await toolkit.assess_patches(state.inventory)

    try:
        ctx = _json.dumps(
            {"assets": len(state.inventory), "patches": len(assessments)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ASSESS_PATCHES,
            user_prompt=f"Patch assessment context:\n{ctx}",
            schema=PatchAssessmentOutput,
        )
        if hasattr(llm_result, "patches_assessed"):
            logger.info("llm_enhanced", node="assess_patches")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="assess_patches")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "assess_patches",
        f"{len(state.inventory)} assets",
        f"{len(assessments)} patches assessed",
        elapsed,
        "patch_analyzer",
    )

    return {
        "patch_assessments": assessments,
        "stage": APMStage.SCHEDULE_DEPLOYMENT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_patches",
    }


async def schedule_deployment(
    state: AutonomousPatchManagerState,
) -> dict[str, Any]:
    """Schedule patch deployments."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    schedules = await toolkit.schedule_deployment(
        state.patch_assessments,
        state.config,
    )

    try:
        ctx = _json.dumps(
            {"assessments": len(state.patch_assessments), "schedules": len(schedules)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_SCHEDULE,
            user_prompt=f"Schedule context:\n{ctx}",
            schema=ScheduleOutput,
        )
        if hasattr(llm_result, "scheduled_count"):
            logger.info("llm_enhanced", node="schedule_deployment")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="schedule_deployment")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "schedule_deployment",
        f"{len(state.patch_assessments)} assessments",
        f"{len(schedules)} deployments scheduled",
        elapsed,
        "scheduler",
    )

    return {
        "deployment_schedules": schedules,
        "stage": APMStage.EXECUTE_PATCHES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "schedule_deployment",
    }


async def execute_patches(
    state: AutonomousPatchManagerState,
) -> dict[str, Any]:
    """Execute scheduled patch deployments."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.execute_patches(state.deployment_schedules)

    try:
        ctx = _json.dumps(
            {"schedules": len(state.deployment_schedules), "results": len(results)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_EXECUTE,
            user_prompt=f"Execution context:\n{ctx}",
            schema=ExecutionOutput,
        )
        if hasattr(llm_result, "executed_count"):
            logger.info("llm_enhanced", node="execute_patches")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="execute_patches")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "execute_patches",
        f"{len(state.deployment_schedules)} schedules",
        f"{len(results)} patches executed",
        elapsed,
        "patch_executor",
    )

    return {
        "execution_results": results,
        "stage": APMStage.VALIDATE_RESULTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "execute_patches",
    }


async def validate_results(
    state: AutonomousPatchManagerState,
) -> dict[str, Any]:
    """Validate patch execution results."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    validations = await toolkit.validate_results(state.execution_results)

    try:
        ctx = _json.dumps(
            {"executions": len(state.execution_results), "validations": len(validations)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_VALIDATE,
            user_prompt=f"Validation context:\n{ctx}",
            schema=ValidationOutput,
        )
        if hasattr(llm_result, "healthy_count"):
            logger.info("llm_enhanced", node="validate_results")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="validate_results")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "validate_results",
        f"{len(state.execution_results)} executions",
        f"{len(validations)} validations",
        elapsed,
        "validator",
    )

    return {
        "validation_results": validations,
        "stage": APMStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "validate_results",
    }


async def generate_report(
    state: AutonomousPatchManagerState,
) -> dict[str, Any]:
    """Generate final patch management report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report = {
        "request_id": state.request_id,
        "assets_scanned": len(state.inventory),
        "patches_assessed": len(state.patch_assessments),
        "deployments_scheduled": len(state.deployment_schedules),
        "patches_executed": len(state.execution_results),
        "validations_completed": len(state.validation_results),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric("patch_duration_ms", float(duration_ms))

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "generate_report",
        f"finalizing {state.request_id}",
        f"report complete in {duration_ms}ms",
        elapsed,
        None,
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
