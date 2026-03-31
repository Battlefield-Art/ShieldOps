"""Node implementations for the Security Mesh
Orchestrator Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_mesh_orchestrator.models import (
    ReasoningStep,
    SecurityMeshOrchestratorState,
    SMOStage,
)
from shieldops.agents.security_mesh_orchestrator.prompts import (
    SYSTEM_ANALYSIS,
    SYSTEM_ANOMALY,
    SYSTEM_DISCOVERY,
    SYSTEM_REPORT,
    AnomalyDetectionOutput,
    MeshAnalysisOutput,
    MeshReportOutput,
    ServiceDiscoveryOutput,
)
from shieldops.agents.security_mesh_orchestrator.tools import (
    SecurityMeshOrchestratorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityMeshOrchestratorToolkit | None = None


def set_toolkit(
    toolkit: SecurityMeshOrchestratorToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SecurityMeshOrchestratorToolkit:
    if _toolkit is None:
        return SecurityMeshOrchestratorToolkit()
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
# Node: discover_services
# ------------------------------------------------------------------


async def discover_services(
    state: SecurityMeshOrchestratorState,
) -> dict[str, Any]:
    """Discover all services in the target mesh
    namespaces and assess sidecar injection status."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    services = await toolkit.discover_services(
        namespaces=state.target_namespaces,
        platform=state.platform.value,
        scope=state.scope,
    )

    svc_list: list[dict[str, Any]] = list(services)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "mesh_name": state.mesh_name,
                "platform": state.platform.value,
                "namespaces": state.target_namespaces,
                "scope": state.scope,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_DISCOVERY,
            user_prompt=f"Discover services for:\n{ctx}",
            schema=ServiceDiscoveryOutput,
        )
        if llm_out.services:  # type: ignore[union-attr]
            svc_list = [
                *svc_list,
                *llm_out.services,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="discover_services",
            count=len(llm_out.services),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="discover_services",
        )

    step = _step(
        state.reasoning_chain,
        "discover_services",
        f"Namespaces: {len(state.target_namespaces)}, platform={state.platform}",
        f"Discovered {len(svc_list)} services",
        start,
        "mesh_discovery",
    )

    return {
        "services": svc_list,
        "total_services": len(svc_list),
        "stage": SMOStage.DISCOVER_SERVICES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "discover_services",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: map_mesh
# ------------------------------------------------------------------


async def map_mesh(
    state: SecurityMeshOrchestratorState,
) -> dict[str, Any]:
    """Map the full service mesh topology including
    dependencies and traffic routes."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    topology = await toolkit.map_service_mesh(
        services=state.services,
        platform=state.platform.value,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "service_count": len(state.services),
                "services_sample": state.services[:5],
                "platform": state.platform.value,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ANALYSIS,
            user_prompt=f"Analyze mesh topology:\n{ctx}",
            schema=MeshAnalysisOutput,
        )
        if llm_out.weak_links:  # type: ignore[union-attr]
            topology.update(
                {
                    "topology_score": llm_out.topology_score,  # type: ignore[union-attr]
                    "weak_links": llm_out.weak_links,  # type: ignore[union-attr]
                    "policy_gaps": llm_out.policy_gaps,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="map_mesh",
            weak_links=len(llm_out.weak_links),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="map_mesh",
        )

    step = _step(
        state.reasoning_chain,
        "map_mesh",
        f"Mapping {len(state.services)} services",
        "Mesh topology mapped",
        start,
        "topology_mapper",
    )

    return {
        "topology": topology,
        "stage": SMOStage.MAP_MESH,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "map_mesh",
    }


# ------------------------------------------------------------------
# Node: enforce_mtls
# ------------------------------------------------------------------


async def enforce_mtls(
    state: SecurityMeshOrchestratorState,
) -> dict[str, Any]:
    """Enforce and validate mTLS across all mesh
    namespaces."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    mtls_status = await toolkit.enforce_mtls(
        namespaces=state.target_namespaces,
        topology=state.topology,
    )

    # Calculate coverage
    compliant = sum(1 for s in mtls_status if s.get("compliant"))
    total = max(len(mtls_status), 1)
    coverage = compliant / total

    step = _step(
        state.reasoning_chain,
        "enforce_mtls",
        f"Enforcing mTLS on {len(state.target_namespaces)} namespaces",
        f"mTLS coverage: {coverage:.0%}",
        start,
        "mtls_enforcer",
    )

    return {
        "mtls_status": mtls_status,
        "mtls_coverage": coverage,
        "stage": SMOStage.ENFORCE_MTLS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "enforce_mtls",
    }


# ------------------------------------------------------------------
# Node: monitor_traffic
# ------------------------------------------------------------------


async def monitor_traffic(
    state: SecurityMeshOrchestratorState,
) -> dict[str, Any]:
    """Monitor east-west traffic patterns for security
    analysis."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    traffic_data = await toolkit.monitor_traffic(
        topology=state.topology,
        services=state.services,
    )

    step = _step(
        state.reasoning_chain,
        "monitor_traffic",
        f"Monitoring traffic for {len(state.services)} services",
        f"Collected {len(traffic_data)} traffic records",
        start,
        "traffic_monitor",
    )

    return {
        "traffic_data": traffic_data,
        "stage": SMOStage.MONITOR_TRAFFIC,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "monitor_traffic",
    }


# ------------------------------------------------------------------
# Node: detect_anomalies
# ------------------------------------------------------------------


async def detect_anomalies(
    state: SecurityMeshOrchestratorState,
) -> dict[str, Any]:
    """Detect anomalous traffic patterns in mesh
    communication."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    anomalies = await toolkit.detect_mesh_anomalies(
        traffic_data=state.traffic_data,
        topology=state.topology,
    )

    anomaly_list: list[dict[str, Any]] = list(anomalies)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "traffic_count": len(state.traffic_data),
                "traffic_sample": state.traffic_data[:5],
                "service_count": state.total_services,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ANOMALY,
            user_prompt=f"Detect anomalies:\n{ctx}",
            schema=AnomalyDetectionOutput,
        )
        if llm_out.anomalies:  # type: ignore[union-attr]
            rand_id = random.randint(1000, 9999)  # noqa: S311
            anomaly_list.append(
                {
                    "anomaly_id": f"llm-{rand_id}",
                    "risk_score": llm_out.risk_score,  # type: ignore[union-attr]
                    "patterns": llm_out.patterns,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="detect_anomalies",
            anomalies=len(llm_out.anomalies),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_anomalies",
        )

    risk = min(10.0, len(anomaly_list) * 1.5) if anomaly_list else 0.0

    step = _step(
        state.reasoning_chain,
        "detect_anomalies",
        f"Analyzing {len(state.traffic_data)} traffic records",
        f"Detected {len(anomaly_list)} anomalies",
        start,
        "anomaly_detector",
    )

    return {
        "anomalies": anomaly_list,
        "anomalies_detected": len(anomaly_list),
        "risk_score": risk,
        "stage": SMOStage.DETECT_ANOMALIES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_anomalies",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: SecurityMeshOrchestratorState,
) -> dict[str, Any]:
    """Generate the final mesh security assessment report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report = await toolkit.generate_report(
        services=state.services,
        topology=state.topology,
        mtls_status=state.mtls_status,
        anomalies=state.anomalies,
        risk_score=state.risk_score,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "mesh_name": state.mesh_name,
                "platform": state.platform.value,
                "total_services": state.total_services,
                "mtls_coverage": state.mtls_coverage,
                "anomalies_detected": state.anomalies_detected,
                "risk_score": state.risk_score,
                "anomalies_sample": state.anomalies[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate mesh report:\n{ctx}",
            schema=MeshReportOutput,
        )
        if isinstance(llm_out, MeshReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "mtls_assessment": llm_out.mtls_assessment,
                    "recommendations": llm_out.recommendations,
                    "risk_rating": llm_out.risk_rating,
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
        "mesh_security_score",
        10.0 - state.risk_score,
        {"mesh": state.mesh_name},
    )

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.total_services} services",
        f"Report generated, risk={state.risk_score:.1f}",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": SMOStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
