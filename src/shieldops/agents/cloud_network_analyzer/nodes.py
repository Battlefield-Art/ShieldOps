"""Node implementations for the Cloud Network Analyzer
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.cloud_network_analyzer.models import (
    CloudNetworkAnalyzerState,
    CNAStage,
    ReasoningStep,
)
from shieldops.agents.cloud_network_analyzer.prompts import (
    SYSTEM_REPORT,
    SYSTEM_ROUTES,
    SYSTEM_SEGMENTATION,
    SYSTEM_TOPOLOGY,
    ExposureReportOutput,
    RouteAuditOutput,
    SegmentationAuditOutput,
    TopologyAnalysisOutput,
)
from shieldops.agents.cloud_network_analyzer.tools import (
    CloudNetworkAnalyzerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: CloudNetworkAnalyzerToolkit | None = None


def _get_toolkit() -> CloudNetworkAnalyzerToolkit:
    if _toolkit is None:
        return CloudNetworkAnalyzerToolkit()
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
# Node: discover_topology
# ------------------------------------------------------------------


async def discover_topology(
    state: CloudNetworkAnalyzerState,
) -> dict[str, Any]:
    """Discover cloud network topology across target
    VPCs and provider accounts."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    topology = await toolkit.discover_topology(
        provider=state.target_provider.value,
        target_vpcs=state.target_vpcs,
        scope=state.scan_scope,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "provider": state.target_provider.value,
                "vpc_count": len(state.target_vpcs),
                "scope": state.scan_scope,
                "topology_count": len(topology),
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_TOPOLOGY,
            user_prompt=f"Analyze topology:\n{ctx}",
            schema=TopologyAnalysisOutput,
        )
        if llm_out.peering_risks:  # type: ignore[union-attr]
            topology.append(
                {
                    "source": "llm_analysis",
                    "vpc_count": llm_out.vpc_count,  # type: ignore[union-attr]
                    "peering_risks": llm_out.peering_risks,  # type: ignore[union-attr]
                    "summary": llm_out.topology_summary,  # type: ignore[union-attr]
                    "recommendations": llm_out.recommendations,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="discover_topology",
            risks=len(llm_out.peering_risks),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="discover_topology",
        )

    total = sum(t.get("total_resources", 0) for t in topology)

    step = _step(
        state.reasoning_chain,
        "discover_topology",
        f"Provider={state.target_provider}, VPCs={len(state.target_vpcs)}",
        f"Discovered {len(topology)} topology items, {total} resources",
        start,
        "cloud_connector",
    )

    return {
        "topology": topology,
        "total_resources": total,
        "stage": CNAStage.DISCOVER_TOPOLOGY,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "discover_topology",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: analyze_routes
# ------------------------------------------------------------------


async def analyze_routes(
    state: CloudNetworkAnalyzerState,
) -> dict[str, Any]:
    """Analyze route tables across discovered VPCs for
    anomalies and security risks."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    route_analyses = await toolkit.analyze_routes(
        topology=state.topology,
        provider=state.target_provider.value,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "provider": state.target_provider.value,
                "topology_count": len(state.topology),
                "topology_sample": state.topology[:3],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ROUTES,
            user_prompt=f"Audit routes:\n{ctx}",
            schema=RouteAuditOutput,
        )
        if llm_out.anomalous_routes:  # type: ignore[union-attr]
            rand_id = random.randint(1000, 9999)  # noqa: S311
            route_analyses.append(
                {
                    "analysis_id": f"llm-{rand_id}",
                    "anomalous_routes": llm_out.anomalous_routes,  # type: ignore[union-attr]
                    "internet_facing_count": llm_out.internet_facing_count,  # type: ignore[union-attr]
                    "risk_score": llm_out.risk_score,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="analyze_routes",
            anomalies=len(llm_out.anomalous_routes),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_routes",
        )

    step = _step(
        state.reasoning_chain,
        "analyze_routes",
        f"Analyzing routes for {len(state.topology)} topology items",
        f"Produced {len(route_analyses)} route analyses",
        start,
        "route_analyzer",
    )

    return {
        "route_analyses": route_analyses,
        "stage": CNAStage.ANALYZE_ROUTES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_routes",
    }


# ------------------------------------------------------------------
# Node: check_segmentation
# ------------------------------------------------------------------


async def check_segmentation(
    state: CloudNetworkAnalyzerState,
) -> dict[str, Any]:
    """Check network segmentation and isolation
    boundaries for policy violations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    segmentation = await toolkit.check_segmentation(
        topology=state.topology,
        route_analyses=state.route_analyses,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "topology_count": len(state.topology),
                "route_analyses_count": len(state.route_analyses),
                "route_sample": state.route_analyses[:3],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_SEGMENTATION,
            user_prompt=f"Check segmentation:\n{ctx}",
            schema=SegmentationAuditOutput,
        )
        if llm_out.violations:  # type: ignore[union-attr]
            segmentation.append(
                {
                    "source": "llm_analysis",
                    "isolation_score": llm_out.isolation_score,  # type: ignore[union-attr]
                    "violations": llm_out.violations,  # type: ignore[union-attr]
                    "cross_segment_risks": llm_out.cross_segment_risks,  # type: ignore[union-attr]
                    "compliant": llm_out.compliant,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="check_segmentation",
            violations=len(llm_out.violations),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="check_segmentation",
        )

    scores = [s.get("isolation_score", 0.0) for s in segmentation]
    avg_score = sum(scores) / len(scores) if scores else 0.0

    step = _step(
        state.reasoning_chain,
        "check_segmentation",
        f"Checking {len(state.topology)} topology segments",
        f"{len(segmentation)} results, avg_score={avg_score:.2f}",
        start,
        "segmentation_engine",
    )

    return {
        "segmentation_results": segmentation,
        "segmentation_score": avg_score,
        "stage": CNAStage.CHECK_SEGMENTATION,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "check_segmentation",
    }


# ------------------------------------------------------------------
# Node: detect_exposure
# ------------------------------------------------------------------


async def detect_exposure(
    state: CloudNetworkAnalyzerState,
) -> dict[str, Any]:
    """Detect network exposure: public IPs, open ports,
    and permissive security group rules."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    findings = await toolkit.detect_exposure(
        topology=state.topology,
        segmentation=state.segmentation_results,
    )

    critical = 0
    for f in findings:
        if hasattr(f, "get") and f.get("exposure_level") == "critical":
            critical += 1

    step = _step(
        state.reasoning_chain,
        "detect_exposure",
        f"Scanning {len(state.topology)} topology items",
        f"{len(findings)} exposures, {critical} critical",
        start,
        "exposure_scanner",
    )

    return {
        "exposure_findings": findings,
        "exposure_count": len(findings),
        "critical_exposures": critical,
        "stage": CNAStage.DETECT_EXPOSURE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_exposure",
    }


# ------------------------------------------------------------------
# Node: recommend
# ------------------------------------------------------------------


async def recommend(
    state: CloudNetworkAnalyzerState,
) -> dict[str, Any]:
    """Generate prioritized remediation recommendations
    from exposure findings."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    recommendations = await toolkit.recommend_changes(
        findings=state.exposure_findings,
        compliance_framework=state.compliance_framework,
    )

    step = _step(
        state.reasoning_chain,
        "recommend",
        f"Processing {len(state.exposure_findings)} findings",
        f"Generated {len(recommendations)} recommendations",
        start,
        "recommender",
    )

    return {
        "recommendations": recommendations,
        "stage": CNAStage.RECOMMEND,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "recommend",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: CloudNetworkAnalyzerState,
) -> dict[str, Any]:
    """Generate the final network exposure report with
    executive summary and recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {
        "provider": state.target_provider.value,
        "total_resources": state.total_resources,
        "exposure_count": state.exposure_count,
        "critical_exposures": state.critical_exposures,
        "segmentation_score": state.segmentation_score,
    }

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "provider": state.target_provider.value,
                "total_resources": state.total_resources,
                "exposure_count": state.exposure_count,
                "critical_exposures": state.critical_exposures,
                "segmentation_score": state.segmentation_score,
                "findings_sample": state.exposure_findings[:5],
                "recommendations": state.recommendations[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate exposure report:\n{ctx}",
            schema=ExposureReportOutput,
        )
        if isinstance(llm_out, ExposureReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "critical_findings": llm_out.critical_findings,
                    "recommendations": llm_out.recommendations,
                    "risk_rating": llm_out.risk_rating,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                findings=len(llm_out.critical_findings),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    # Record metrics
    await toolkit.record_metric(
        request_id=state.request_id,
        outcome={
            "exposure_count": state.exposure_count,
            "critical_exposures": state.critical_exposures,
            "segmentation_score": state.segmentation_score,
            "total_resources": state.total_resources,
        },
    )

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.exposure_count} exposures",
        f"Report generated, {state.critical_exposures} critical",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": CNAStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
