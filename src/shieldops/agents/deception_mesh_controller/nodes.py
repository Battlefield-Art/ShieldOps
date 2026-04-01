"""Node implementations for the Deception Mesh Controller."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.deception_mesh_controller.models import (
    DeceptionMeshControllerState,
    DMCStage,
    ReasoningStep,
)
from shieldops.agents.deception_mesh_controller.prompts import (
    SYSTEM_ATTACKER,
    SYSTEM_DEPLOY,
    SYSTEM_INTEL,
    SYSTEM_MONITOR,
    SYSTEM_PLAN,
    AttackerOutput,
    DeploymentPlanOutput,
    DeployOutput,
    IntelOutput,
    MonitorOutput,
)
from shieldops.agents.deception_mesh_controller.tools import (
    DeceptionMeshControllerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: DeceptionMeshControllerToolkit | None = None


def set_toolkit(
    toolkit: DeceptionMeshControllerToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> DeceptionMeshControllerToolkit:
    if _toolkit is None:
        return DeceptionMeshControllerToolkit()
    return _toolkit


def _step(
    state: DeceptionMeshControllerState,
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


async def plan_deployment(
    state: DeceptionMeshControllerState,
) -> dict[str, Any]:
    """Plan decoy deployment."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    plans = await toolkit.plan_deployment(state.config)

    try:
        ctx = _json.dumps(
            {"count": len(plans)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_PLAN,
            user_prompt=f"Deployment planning context:\n{ctx}",
            schema=DeploymentPlanOutput,
        )
        if hasattr(llm_result, "plans_created"):
            logger.info(
                "llm_enhanced",
                node="plan_deployment",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="plan_deployment",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "plan_deployment",
        f"config={state.config}",
        f"created {len(plans)} plans",
        elapsed,
        "deception_platform",
    )
    await toolkit.record_metric(
        "plans_created",
        float(len(plans)),
    )

    return {
        "deployment_plans": plans,
        "stage": DMCStage.DEPLOY_DECOYS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "plan_deployment",
        "session_start": start,
    }


async def deploy_decoys(
    state: DeceptionMeshControllerState,
) -> dict[str, Any]:
    """Deploy deception assets."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    decoys = await toolkit.deploy_decoys(
        state.deployment_plans,
    )

    try:
        ctx = _json.dumps(
            {
                "plans": len(state.deployment_plans),
                "deployed": len(decoys),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_DEPLOY,
            user_prompt=f"Deployment context:\n{ctx}",
            schema=DeployOutput,
        )
        if hasattr(llm_result, "decoys_deployed"):
            logger.info(
                "llm_enhanced",
                node="deploy_decoys",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="deploy_decoys",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "deploy_decoys",
        f"deploying {len(state.deployment_plans)} plans",
        f"{len(decoys)} decoys deployed",
        elapsed,
        "deception_platform",
    )

    return {
        "deployed_decoys": decoys,
        "stage": DMCStage.MONITOR_INTERACTIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "deploy_decoys",
    }


async def monitor_interactions(
    state: DeceptionMeshControllerState,
) -> dict[str, Any]:
    """Monitor interactions with deployed decoys."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    interactions = await toolkit.monitor_interactions(
        state.deployed_decoys,
    )
    critical = sum(1 for i in interactions if i.get("severity") == "critical")

    try:
        ctx = _json.dumps(
            {
                "decoys": len(state.deployed_decoys),
                "interactions": len(interactions),
                "critical": critical,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_MONITOR,
            user_prompt=f"Monitoring context:\n{ctx}",
            schema=MonitorOutput,
        )
        if hasattr(llm_result, "interactions_detected"):
            logger.info(
                "llm_enhanced",
                node="monitor_interactions",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="monitor_interactions",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "monitor_interactions",
        f"monitoring {len(state.deployed_decoys)} decoys",
        f"{len(interactions)} interactions, {critical} critical",
        elapsed,
        "deception_platform",
    )
    await toolkit.record_metric(
        "interactions_detected",
        float(len(interactions)),
    )

    return {
        "interactions": interactions,
        "stage": DMCStage.ANALYZE_ATTACKER,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "monitor_interactions",
    }


async def analyze_attacker(
    state: DeceptionMeshControllerState,
) -> dict[str, Any]:
    """Analyze attacker behavior from interactions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    profiles = await toolkit.analyze_attacker(
        state.interactions,
    )

    try:
        ctx = _json.dumps(
            {
                "interactions": len(state.interactions),
                "profiles": len(profiles),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ATTACKER,
            user_prompt=f"Attacker analysis context:\n{ctx}",
            schema=AttackerOutput,
        )
        if hasattr(llm_result, "profiles_created"):
            logger.info(
                "llm_enhanced",
                node="analyze_attacker",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_attacker",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "analyze_attacker",
        f"analyzing {len(state.interactions)} interactions",
        f"{len(profiles)} attacker profiles",
        elapsed,
        "threat_intel",
    )

    return {
        "attacker_profiles": profiles,
        "stage": DMCStage.CORRELATE_INTEL,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_attacker",
    }


async def correlate_intel(
    state: DeceptionMeshControllerState,
) -> dict[str, Any]:
    """Correlate deception intel with threat data."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    correlations = await toolkit.correlate_intel(
        state.attacker_profiles,
    )

    try:
        ctx = _json.dumps(
            {
                "profiles": len(state.attacker_profiles),
                "correlations": len(correlations),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_INTEL,
            user_prompt=f"Intel correlation context:\n{ctx}",
            schema=IntelOutput,
        )
        if hasattr(llm_result, "correlations_found"):
            logger.info(
                "llm_enhanced",
                node="correlate_intel",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="correlate_intel",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "correlate_intel",
        f"correlating {len(state.attacker_profiles)} profiles",
        f"{len(correlations)} correlations",
        elapsed,
        "threat_intel",
    )
    await toolkit.record_metric(
        "intel_correlations",
        float(len(correlations)),
    )

    return {
        "intel_correlations": correlations,
        "stage": DMCStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "correlate_intel",
    }


async def generate_report(
    state: DeceptionMeshControllerState,
) -> dict[str, Any]:
    """Generate final deception mesh report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int(
            (datetime.now(UTC) - state.session_start).total_seconds() * 1000,
        )

    report = {
        "request_id": state.request_id,
        "plans_created": len(state.deployment_plans),
        "decoys_deployed": len(state.deployed_decoys),
        "interactions": len(state.interactions),
        "attacker_profiles": len(state.attacker_profiles),
        "intel_correlations": len(state.intel_correlations),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric(
        "scan_duration_ms",
        float(duration_ms),
    )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
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
