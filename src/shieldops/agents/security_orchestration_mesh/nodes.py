"""Node implementations for the Security Orchestration Mesh."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_orchestration_mesh.models import (
    ReasoningStep,
    SecurityOrchestrationMeshState,
    SOMStage,
)
from shieldops.agents.security_orchestration_mesh.prompts import (
    SYSTEM_AGGREGATE,
    SYSTEM_COORDINATE,
    SYSTEM_DISCOVER_REGIONS,
    SYSTEM_DISTRIBUTE,
    SYSTEM_MAP_CAPABILITIES,
    AggregationOutput,
    CapabilityMapOutput,
    CoordinationOutput,
    RegionDiscoveryOutput,
    TaskDistributionOutput,
)
from shieldops.agents.security_orchestration_mesh.tools import (
    SecurityOrchestrationMeshToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityOrchestrationMeshToolkit | None = None


def _get_toolkit() -> SecurityOrchestrationMeshToolkit:
    if _toolkit is None:
        return SecurityOrchestrationMeshToolkit()
    return _toolkit


def _step(
    state: SecurityOrchestrationMeshState,
    action: str,
    input_summary: str,
    output_summary: str,
    duration_ms: int,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Create a reasoning step."""
    return ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=duration_ms,
        tool_used=tool_used,
    )


async def discover_regions(
    state: SecurityOrchestrationMeshState,
) -> dict[str, Any]:
    """Discover regions across cloud providers."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.discover_regions(state.config)
    healthy = sum(1 for r in raw if r.get("status") == "healthy")

    try:
        ctx = _json.dumps(
            {"providers": state.config.get("providers", []), "region_count": len(raw)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_DISCOVER_REGIONS,
            user_prompt=f"Region discovery context:\n{ctx}",
            schema=RegionDiscoveryOutput,
        )
        if hasattr(llm_result, "total_regions"):
            logger.info("llm_enhanced", node="discover_regions")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="discover_regions")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "discover_regions",
        f"providers={state.config.get('providers', [])}",
        f"found {len(raw)} regions, {healthy} healthy",
        elapsed,
        "cloud_client",
    )
    await toolkit.record_metric("regions_discovered", float(len(raw)))

    return {
        "regions": raw,
        "stage": SOMStage.MAP_CAPABILITIES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "discover_regions",
        "session_start": start,
    }


async def map_capabilities(
    state: SecurityOrchestrationMeshState,
) -> dict[str, Any]:
    """Map security capabilities per region."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    caps = await toolkit.map_capabilities(state.regions)
    underutilized = sum(1 for c in caps if c.get("utilization", 0) < 0.3)

    try:
        ctx = _json.dumps(
            {"region_count": len(state.regions), "capability_count": len(caps)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_MAP_CAPABILITIES,
            user_prompt=f"Capability mapping context:\n{ctx}",
            schema=CapabilityMapOutput,
        )
        if hasattr(llm_result, "underutilized"):
            logger.info("llm_enhanced", node="map_capabilities")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="map_capabilities")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "map_capabilities",
        f"mapping {len(state.regions)} regions",
        f"{len(caps)} capabilities, {underutilized} underutilized",
        elapsed,
        "mesh_controller",
    )

    return {
        "capabilities": caps,
        "stage": SOMStage.DISTRIBUTE_TASKS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "map_capabilities",
    }


async def distribute_tasks(
    state: SecurityOrchestrationMeshState,
) -> dict[str, Any]:
    """Distribute security tasks across regions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    tasks = await toolkit.distribute_tasks(state.capabilities, state.config)

    try:
        ctx = _json.dumps(
            {"capability_count": len(state.capabilities), "task_count": len(tasks)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_DISTRIBUTE,
            user_prompt=f"Task distribution context:\n{ctx}",
            schema=TaskDistributionOutput,
        )
        if hasattr(llm_result, "tasks_distributed"):
            logger.info("llm_enhanced", node="distribute_tasks")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="distribute_tasks")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "distribute_tasks",
        f"distributing across {len(state.capabilities)} capabilities",
        f"distributed {len(tasks)} tasks",
        elapsed,
        "task_scheduler",
    )
    await toolkit.record_metric("tasks_distributed", float(len(tasks)))

    return {
        "distributed_tasks": tasks,
        "stage": SOMStage.COORDINATE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "distribute_tasks",
    }


async def coordinate_execution(
    state: SecurityOrchestrationMeshState,
) -> dict[str, Any]:
    """Coordinate task execution across regions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.coordinate_execution(state.distributed_tasks)

    try:
        ctx = _json.dumps(
            {"task_count": len(state.distributed_tasks), "results": results[:5]},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_COORDINATE,
            user_prompt=f"Coordination context:\n{ctx}",
            schema=CoordinationOutput,
        )
        if hasattr(llm_result, "completion_rate"):
            logger.info("llm_enhanced", node="coordinate_execution")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="coordinate_execution")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "coordinate_execution",
        f"coordinating {len(state.distributed_tasks)} tasks",
        f"{len(results)} coordination results",
        elapsed,
        "mesh_controller",
    )

    return {
        "coordination_results": results,
        "stage": SOMStage.AGGREGATE_RESULTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "coordinate_execution",
    }


async def aggregate_results(
    state: SecurityOrchestrationMeshState,
) -> dict[str, Any]:
    """Aggregate results from all regions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    agg = await toolkit.aggregate_results(
        state.coordination_results,
        state.distributed_tasks,
    )

    try:
        ctx = _json.dumps(
            {"coordination_count": len(state.coordination_results), "aggregated": agg[:5]},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_AGGREGATE,
            user_prompt=f"Aggregation context:\n{ctx}",
            schema=AggregationOutput,
        )
        if hasattr(llm_result, "total_findings"):
            logger.info("llm_enhanced", node="aggregate_results")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="aggregate_results")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "aggregate_results",
        f"aggregating {len(state.coordination_results)} results",
        f"{len(agg)} aggregated entries",
        elapsed,
        "aggregator",
    )

    return {
        "aggregated_results": agg,
        "stage": SOMStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "aggregate_results",
    }


async def generate_report(
    state: SecurityOrchestrationMeshState,
) -> dict[str, Any]:
    """Generate final orchestration mesh report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report = {
        "request_id": state.request_id,
        "regions": len(state.regions),
        "capabilities": len(state.capabilities),
        "tasks": len(state.distributed_tasks),
        "coordination_results": len(state.coordination_results),
        "aggregated_findings": len(state.aggregated_results),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric("scan_duration_ms", float(duration_ms))

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
