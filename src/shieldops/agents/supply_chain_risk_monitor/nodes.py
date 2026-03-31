"""Node implementations for the Supply Chain Risk Monitor
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.supply_chain_risk_monitor.models import (
    ReasoningStep,
    SCRMStage,
    SupplyChainRiskMonitorState,
)
from shieldops.agents.supply_chain_risk_monitor.prompts import (
    SYSTEM_DEPENDENCIES,
    SYSTEM_IMPACT,
    SYSTEM_REPORT,
    SYSTEM_RISKS,
    DependencyAnalysisOutput,
    ImpactAssessmentOutput,
    RiskDetectionOutput,
    SupplyChainReportOutput,
)
from shieldops.agents.supply_chain_risk_monitor.tools import (
    SupplyChainRiskMonitorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SupplyChainRiskMonitorToolkit | None = None


def set_toolkit(
    toolkit: SupplyChainRiskMonitorToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SupplyChainRiskMonitorToolkit:
    if _toolkit is None:
        return SupplyChainRiskMonitorToolkit()
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
# Node: scan_supply_chain
# ------------------------------------------------------------------


async def scan_supply_chain(
    state: SupplyChainRiskMonitorState,
) -> dict[str, Any]:
    """Scan the software supply chain for all direct
    and transitive dependencies."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.scan_supply_chain(
        scan_target=state.scan_target,
        ecosystems=state.ecosystems,
        include_transitive=state.include_transitive,
    )

    dependencies: list[dict[str, Any]] = list(results)

    step = _step(
        state.reasoning_chain,
        "scan_supply_chain",
        f"Target: {state.scan_target}",
        f"Found {len(dependencies)} dependencies",
        start,
        "dependency_scanner",
    )

    return {
        "dependencies": dependencies,
        "total_dependencies": len(dependencies),
        "stage": SCRMStage.SCAN_SUPPLY_CHAIN,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "scan_supply_chain",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: analyze_dependencies
# ------------------------------------------------------------------


async def analyze_dependencies(
    state: SupplyChainRiskMonitorState,
) -> dict[str, Any]:
    """Analyze dependencies for risk indicators including
    typosquatting and maintainer trust."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    analyses = await toolkit.analyze_dependencies(
        dependencies=state.dependencies,
        ecosystems=state.ecosystems,
    )

    analyses_list: list[dict[str, Any]] = list(analyses)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "dep_count": len(state.dependencies),
                "ecosystems": state.ecosystems,
                "dependencies_sample": state.dependencies[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_DEPENDENCIES,
            user_prompt=(f"Analyze dependencies:\n{ctx}"),
            schema=DependencyAnalysisOutput,
        )
        if llm_out.risk_indicators:  # type: ignore[union-attr]
            _rid = random.randint(1000, 9999)  # noqa: S311
            analyses_list.append(
                {
                    "analysis_id": f"llm-{_rid}",
                    "risk_indicators": llm_out.risk_indicators,  # type: ignore[union-attr]
                    "typosquat_candidates": llm_out.typosquat_candidates,  # type: ignore[union-attr]
                    "confidence": llm_out.confidence,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="analyze_dependencies",
            indicators=len(llm_out.risk_indicators),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_dependencies",
        )

    step = _step(
        state.reasoning_chain,
        "analyze_dependencies",
        f"Analyzing {len(state.dependencies)} deps",
        f"Produced {len(analyses_list)} analyses",
        start,
        "dependency_analyzer",
    )

    return {
        "analyses": analyses_list,
        "stage": SCRMStage.ANALYZE_DEPENDENCIES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_dependencies",
    }


# ------------------------------------------------------------------
# Node: detect_risks
# ------------------------------------------------------------------


async def detect_risks(
    state: SupplyChainRiskMonitorState,
) -> dict[str, Any]:
    """Detect supply chain risks from dependency analysis
    results."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    risks = await toolkit.detect_risks(
        analyses=state.analyses,
        dependencies=state.dependencies,
    )

    risks_list: list[dict[str, Any]] = list(risks)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "analyses_count": len(state.analyses),
                "analyses_sample": state.analyses[:5],
                "dep_count": len(state.dependencies),
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_RISKS,
            user_prompt=f"Detect risks:\n{ctx}",
            schema=RiskDetectionOutput,
        )
        if llm_out.categories:  # type: ignore[union-attr]
            _rid = random.randint(1000, 9999)  # noqa: S311
            risks_list.append(
                {
                    "risk_id": f"llm-{_rid}",
                    "risks_found": llm_out.risks_found,  # type: ignore[union-attr]
                    "categories": llm_out.categories,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="detect_risks",
            categories=len(llm_out.categories),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_risks",
        )

    critical = sum(1 for r in risks_list if r.get("severity") == "critical")

    step = _step(
        state.reasoning_chain,
        "detect_risks",
        f"Scanning {len(state.analyses)} analyses",
        f"Detected {len(risks_list)} risks ({critical} critical)",
        start,
        "risk_detector",
    )

    return {
        "risks": risks_list,
        "risks_detected": len(risks_list),
        "critical_risks": critical,
        "stage": SCRMStage.DETECT_RISKS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_risks",
    }


# ------------------------------------------------------------------
# Node: assess_impact
# ------------------------------------------------------------------


async def assess_impact(
    state: SupplyChainRiskMonitorState,
) -> dict[str, Any]:
    """Assess the business impact of detected supply
    chain risks."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments: list[dict[str, Any]] = []

    for risk in state.risks:
        result = await toolkit.assess_impact(
            risk=risk,
            dependencies=state.dependencies,
        )

        # LLM enhancement per risk
        try:
            ctx = _json.dumps(
                {
                    "risk": risk,
                    "dep_count": len(state.dependencies),
                },
                default=str,
            )
            llm_out = await llm_structured(
                system_prompt=SYSTEM_IMPACT,
                user_prompt=(f"Assess impact:\n{ctx}"),
                schema=ImpactAssessmentOutput,
            )
            result = {
                "blast_radius": llm_out.blast_radius,  # type: ignore[union-attr]
                "exploitability": llm_out.exploitability,  # type: ignore[union-attr]
                "business_impact": llm_out.business_impact,  # type: ignore[union-attr]
                "remediation_priority": llm_out.remediation_priority,  # type: ignore[union-attr]
            }
            logger.info(
                "llm_enhanced",
                node="assess_impact",
                impact=llm_out.business_impact,  # type: ignore[union-attr]
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="assess_impact",
            )

        assessments.append(result)

    step = _step(
        state.reasoning_chain,
        "assess_impact",
        f"Assessing {len(state.risks)} risks",
        f"Produced {len(assessments)} assessments",
        start,
        "impact_assessor",
    )

    return {
        "assessments": assessments,
        "stage": SCRMStage.ASSESS_IMPACT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_impact",
    }


# ------------------------------------------------------------------
# Node: mitigate
# ------------------------------------------------------------------


async def mitigate(
    state: SupplyChainRiskMonitorState,
) -> dict[str, Any]:
    """Apply mitigation actions for detected supply
    chain risks."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    mitigations = await toolkit.apply_mitigations(
        risks=state.risks,
        assessments=state.assessments,
    )

    applied = sum(1 for m in mitigations if m.get("applied"))

    step = _step(
        state.reasoning_chain,
        "mitigate",
        f"Mitigating {len(state.risks)} risks",
        f"Applied {applied} mitigations",
        start,
        "mitigation_engine",
    )

    return {
        "mitigations": mitigations,
        "mitigations_applied": applied,
        "stage": SCRMStage.MITIGATE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "mitigate",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: SupplyChainRiskMonitorState,
) -> dict[str, Any]:
    """Generate the final supply chain risk report with
    remediation status and recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    report: dict[str, Any] = {
        "total_dependencies": state.total_dependencies,
        "risks_detected": state.risks_detected,
        "critical_risks": state.critical_risks,
        "mitigations_applied": state.mitigations_applied,
        "duration_ms": duration_ms,
    }

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "scan_target": state.scan_target,
                "total_dependencies": state.total_dependencies,
                "risks_detected": state.risks_detected,
                "critical_risks": state.critical_risks,
                "mitigations_applied": state.mitigations_applied,
                "risks_sample": state.risks[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate supply chain report:\n{ctx}"),
            schema=SupplyChainReportOutput,
        )
        if isinstance(llm_out, SupplyChainReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "slsa_compliance": llm_out.slsa_compliance,
                    "recommendations": llm_out.recommendations,
                    "risk_trend": llm_out.risk_trend,
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
        metric_name="supply_chain_scan",
        value=float(state.risks_detected),
        labels={"target": state.scan_target},
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.risks_detected} risks",
        "Report generated",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": SCRMStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
