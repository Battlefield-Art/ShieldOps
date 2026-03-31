"""Node implementations for the Network Microsegmentation
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.network_microsegmentation.models import (
    NetworkMicrosegmentationState,
    NMSStage,
    ReasoningStep,
)
from shieldops.agents.network_microsegmentation.prompts import (
    SYSTEM_FLOWS,
    SYSTEM_POLICIES,
    SYSTEM_REPORT,
    SYSTEM_TOPOLOGY,
    DeploymentReportOutput,
    FlowAnalysisOutput,
    PolicyGenerationOutput,
    TopologyAnalysisOutput,
)
from shieldops.agents.network_microsegmentation.tools import (
    NetworkMicrosegmentationToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: NetworkMicrosegmentationToolkit | None = None


def set_toolkit(
    toolkit: NetworkMicrosegmentationToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> NetworkMicrosegmentationToolkit:
    if _toolkit is None:
        return NetworkMicrosegmentationToolkit()
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
# Node: map_topology
# ------------------------------------------------------------------


async def map_topology(
    state: NetworkMicrosegmentationState,
) -> dict[str, Any]:
    """Discover network topology and workload
    interconnections for segmentation planning."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.map_topology(
        network_scope=state.network_scope,
        target_zones=state.target_zones,
    )

    topology: list[dict[str, Any]] = list(results)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "network_scope": state.network_scope,
                "target_zones": state.target_zones,
                "segmentation_type": state.segmentation_type.value,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_TOPOLOGY,
            user_prompt=(f"Analyze topology for:\n{ctx}"),
            schema=TopologyAnalysisOutput,
        )
        if llm_out.zones:  # type: ignore[union-attr]
            for zone in llm_out.zones:  # type: ignore[union-attr]
                _rid = random.randint(1000, 9999)  # noqa: S311
                topology.append(
                    {
                        "node_id": f"llm-{_rid}",
                        "zone": zone,
                        "source": "llm",
                    }
                )
        logger.info(
            "llm_enhanced",
            node="map_topology",
            zones=len(llm_out.zones),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="map_topology",
        )

    step = _step(
        state.reasoning_chain,
        "map_topology",
        f"Scope: {state.network_scope}",
        f"Discovered {len(topology)} nodes",
        start,
        "topology_scanner",
    )

    return {
        "topology": topology,
        "total_nodes": len(topology),
        "stage": NMSStage.MAP_TOPOLOGY,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "map_topology",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: analyze_flows
# ------------------------------------------------------------------


async def analyze_flows(
    state: NetworkMicrosegmentationState,
) -> dict[str, Any]:
    """Analyze east-west traffic flows between workloads
    for segmentation planning."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    flows = await toolkit.analyze_flows(
        topology=state.topology,
        target_zones=state.target_zones,
    )

    flows_list: list[dict[str, Any]] = list(flows)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "node_count": len(state.topology),
                "topology_sample": state.topology[:5],
                "zones": state.target_zones,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_FLOWS,
            user_prompt=f"Analyze flows:\n{ctx}",
            schema=FlowAnalysisOutput,
        )
        if llm_out.patterns:  # type: ignore[union-attr]
            _rid = random.randint(1000, 9999)  # noqa: S311
            flows_list.append(
                {
                    "flow_id": f"llm-{_rid}",
                    "suspicious_flows": llm_out.suspicious_flows,  # type: ignore[union-attr]
                    "patterns": llm_out.patterns,  # type: ignore[union-attr]
                    "risk_score": llm_out.risk_score,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="analyze_flows",
            patterns=len(llm_out.patterns),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_flows",
        )

    step = _step(
        state.reasoning_chain,
        "analyze_flows",
        f"Analyzing flows for {len(state.topology)} nodes",
        f"Identified {len(flows_list)} flow records",
        start,
        "flow_analyzer",
    )

    return {
        "flows": flows_list,
        "total_flows": len(flows_list),
        "stage": NMSStage.ANALYZE_FLOWS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_flows",
    }


# ------------------------------------------------------------------
# Node: generate_policies
# ------------------------------------------------------------------


async def generate_policies(
    state: NetworkMicrosegmentationState,
) -> dict[str, Any]:
    """Generate microsegmentation policies from topology
    and flow analysis."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    policies = await toolkit.generate_policies(
        topology=state.topology,
        flows=state.flows,
        segmentation_type=state.segmentation_type.value,
    )

    policies_list: list[dict[str, Any]] = list(policies)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "flow_count": len(state.flows),
                "node_count": len(state.topology),
                "segmentation_type": state.segmentation_type.value,
                "flows_sample": state.flows[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_POLICIES,
            user_prompt=(f"Generate policies:\n{ctx}"),
            schema=PolicyGenerationOutput,
        )
        if llm_out.policies:  # type: ignore[union-attr]
            policies_list.extend(
                llm_out.policies  # type: ignore[union-attr]
            )
        logger.info(
            "llm_enhanced",
            node="generate_policies",
            count=len(llm_out.policies),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_policies",
        )

    step = _step(
        state.reasoning_chain,
        "generate_policies",
        f"Generating from {len(state.flows)} flows",
        f"Generated {len(policies_list)} policies",
        start,
        "policy_engine",
    )

    return {
        "policies": policies_list,
        "policies_generated": len(policies_list),
        "stage": NMSStage.GENERATE_POLICIES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "generate_policies",
    }


# ------------------------------------------------------------------
# Node: validate_policies
# ------------------------------------------------------------------


async def validate_policies(
    state: NetworkMicrosegmentationState,
) -> dict[str, Any]:
    """Validate generated policies for conflicts and
    coverage gaps."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    validations = await toolkit.validate_policies(
        policies=state.policies,
        topology=state.topology,
    )

    step = _step(
        state.reasoning_chain,
        "validate_policies",
        f"Validating {len(state.policies)} policies",
        f"Validated with {len(validations)} results",
        start,
        "policy_validator",
    )

    return {
        "validations": validations,
        "stage": NMSStage.VALIDATE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "validate_policies",
    }


# ------------------------------------------------------------------
# Node: deploy_policies
# ------------------------------------------------------------------


async def deploy_policies(
    state: NetworkMicrosegmentationState,
) -> dict[str, Any]:
    """Deploy validated segmentation policies to the
    network enforcement layer."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    deployments = await toolkit.deploy_policies(
        policies=state.policies,
        enforcement_mode=state.enforcement_mode,
    )

    deployed = sum(1 for d in deployments if d.get("status") == "deployed")

    step = _step(
        state.reasoning_chain,
        "deploy_policies",
        (f"Deploying {len(state.policies)} policies in {state.enforcement_mode} mode"),
        f"Deployed {deployed} policies",
        start,
        "deployment_manager",
    )

    return {
        "deployments": deployments,
        "policies_deployed": deployed,
        "stage": NMSStage.DEPLOY,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "deploy_policies",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: NetworkMicrosegmentationState,
) -> dict[str, Any]:
    """Generate the final microsegmentation report with
    deployment summary and recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    report: dict[str, Any] = {
        "total_nodes": state.total_nodes,
        "total_flows": state.total_flows,
        "policies_generated": state.policies_generated,
        "policies_deployed": state.policies_deployed,
        "duration_ms": duration_ms,
    }

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "network_scope": state.network_scope,
                "segmentation_type": state.segmentation_type.value,
                "total_nodes": state.total_nodes,
                "total_flows": state.total_flows,
                "policies_generated": state.policies_generated,
                "policies_deployed": state.policies_deployed,
                "validations": state.validations[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate segmentation report:\n{ctx}"),
            schema=DeploymentReportOutput,
        )
        if isinstance(llm_out, DeploymentReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "recommendations": llm_out.recommendations,
                    "risk_posture": llm_out.risk_posture,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                recs=len(llm_out.recommendations),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    await toolkit.record_metric(
        metric_name="segmentation_run",
        value=float(state.policies_deployed),
        labels={"scope": state.network_scope},
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.policies_generated} policies",
        "Report generated",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": NMSStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
