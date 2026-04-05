"""Node implementations for the Supply Chain Risk Engine LangGraph workflow.

Each node is an async function that:
1. Queries dependency/vulnerability systems via the toolkit
2. Uses the LLM to analyze and reason about data
3. Updates the SCRE state with findings
4. Records its reasoning step in the audit trail
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.supply_chain_risk_engine.models import (
    BlastRadiusMapping,
    DependencyRecord,
    ReasoningStep,
    RiskAssessment,
    SCREStage,
    SupplyChainRisk,
    SupplyChainRiskEngineState,
    VulnerabilityScan,
)
from shieldops.agents.supply_chain_risk_engine.prompts import (
    SYSTEM_ASSESS_RISK,
    SYSTEM_INVENTORY_DEPENDENCIES,
    SYSTEM_MAP_BLAST_RADIUS,
    SYSTEM_RECOMMEND_MITIGATIONS,
    SYSTEM_SCAN_VULNERABILITIES,
    BlastRadiusAnalysis,
    DependencyInventoryAnalysis,
    MitigationAnalysis,
    RiskAssessmentAnalysis,
    VulnerabilityScanAnalysis,
)
from shieldops.agents.supply_chain_risk_engine.tools import (
    SupplyChainRiskEngineToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

# Module-level toolkit, set by runner at startup.
_toolkit: SupplyChainRiskEngineToolkit | None = None


def set_toolkit(
    toolkit: SupplyChainRiskEngineToolkit,
) -> None:
    """Configure toolkit used by all nodes."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SupplyChainRiskEngineToolkit:
    if _toolkit is None:
        return SupplyChainRiskEngineToolkit()
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


# ---- Node: inventory_dependencies ----


async def inventory_dependencies(
    state: SupplyChainRiskEngineState,
) -> dict[str, Any]:
    """Inventory dependencies across the supply chain."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "scre_inventorying_dependencies",
        request_id=state.request_id,
    )

    scope = state.config.get("scope")
    records = await toolkit.inventory_dependencies(
        tenant_id=state.tenant_id,
        scope=scope,
    )

    types_found = list({r.dependency_type.value for r in records})
    output_summary = f"Inventoried {len(records)} dependencies across {len(types_found)} types."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "dependencies_found": len(records),
                "types": types_found,
                "sources": list({r.source for r in records}),
                "unpinned": sum(1 for r in records if not r.is_pinned),
            },
            default=str,
        )
        llm_result = cast(
            DependencyInventoryAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_INVENTORY_DEPENDENCIES,
                user_prompt=(f"Dependency inventory results:\n{ctx}"),
                schema=DependencyInventoryAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} {len(records)} dependencies."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="inventory_dependencies",
        )

    step = ReasoningStep(
        step_number=1,
        action="inventory_dependencies",
        input_summary="Inventorying supply chain dependencies",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="dependency_inventorier",
    )

    return {
        "dependencies": [r.model_dump() for r in records],
        "dependency_count": len(records),
        "stage": SCREStage.SCAN_VULNERABILITIES,
        "session_start": start,
        "reasoning_chain": [step],
        "current_step": "inventory_dependencies",
    }


# ---- Node: scan_vulnerabilities ----


async def scan_vulnerabilities(
    state: SupplyChainRiskEngineState,
) -> dict[str, Any]:
    """Scan inventoried dependencies for vulnerabilities."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    records = [DependencyRecord.model_validate(d) for d in state.dependencies]

    logger.info(
        "scre_scanning_vulnerabilities",
        request_id=state.request_id,
        dependency_count=len(records),
    )

    scans = await toolkit.scan_vulnerabilities(records)
    critical = sum(1 for s in scans if s.severity == "critical")

    output_summary = (
        f"Scanned {len(records)} dependencies. "
        f"Found {len(scans)} vulnerabilities, "
        f"{critical} critical."
    )

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "dependencies": len(records),
                "vulnerabilities": len(scans),
                "critical": critical,
                "cves": [s.cve_id for s in scans[:15]],
            },
            default=str,
        )
        llm_result = cast(
            VulnerabilityScanAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_SCAN_VULNERABILITIES,
                user_prompt=(f"Vulnerability scan results:\n{ctx}"),
                schema=VulnerabilityScanAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Quality: {llm_result.scan_quality}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="scan_vulnerabilities",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="scan_vulnerabilities",
        input_summary=(f"Scanning {len(records)} dependencies for vulns"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="vulnerability_scanner",
    )

    return {
        "vulnerability_scans": [s.model_dump() for s in scans],
        "vulnerability_count": len(scans),
        "critical_count": critical,
        "stage": SCREStage.ASSESS_RISK,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "scan_vulnerabilities",
    }


# ---- Node: assess_risk ----


async def assess_risk(
    state: SupplyChainRiskEngineState,
) -> dict[str, Any]:
    """Assess risk for each dependency."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    records = [DependencyRecord.model_validate(d) for d in state.dependencies]
    scans = [VulnerabilityScan.model_validate(s) for s in state.vulnerability_scans]

    logger.info(
        "scre_assessing_risk",
        request_id=state.request_id,
        dependency_count=len(records),
    )

    assessments = await toolkit.assess_risk(records, scans)
    high_risk = sum(
        1 for a in assessments if a.risk_level in (SupplyChainRisk.CRITICAL, SupplyChainRisk.HIGH)
    )

    output_summary = f"Assessed {len(assessments)} dependencies. {high_risk} high/critical risk."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "dependencies": len(records),
                "assessments": len(assessments),
                "high_risk": high_risk,
                "risk_levels": [a.risk_level.value for a in assessments],
            },
            default=str,
        )
        llm_result = cast(
            RiskAssessmentAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_ASSESS_RISK,
                user_prompt=(f"Risk assessment results:\n{ctx}"),
                schema=RiskAssessmentAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Risk: {llm_result.risk_level}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_risk",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="assess_risk",
        input_summary=(f"Assessing risk for {len(records)} deps with {len(scans)} vulns"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="risk_assessor",
    )

    return {
        "risk_assessments": [a.model_dump() for a in assessments],
        "stage": SCREStage.MAP_BLAST_RADIUS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_risk",
    }


# ---- Node: map_blast_radius ----


async def map_blast_radius(
    state: SupplyChainRiskEngineState,
) -> dict[str, Any]:
    """Map blast radius for risky dependencies."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments = [RiskAssessment.model_validate(a) for a in state.risk_assessments]

    logger.info(
        "scre_mapping_blast_radius",
        request_id=state.request_id,
        assessment_count=len(assessments),
    )

    mappings = await toolkit.map_blast_radius(assessments)
    wide_blast = sum(1 for m in mappings if m.blast_radius in ("critical", "high"))

    output_summary = f"Mapped {len(mappings)} blast radii. {wide_blast} wide blast radius."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "assessments": len(assessments),
                "mappings": len(mappings),
                "wide_blast": wide_blast,
                "services": list({s for m in mappings for s in m.affected_services}),
            },
            default=str,
        )
        llm_result = cast(
            BlastRadiusAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_MAP_BLAST_RADIUS,
                user_prompt=(f"Blast radius mapping results:\n{ctx}"),
                schema=BlastRadiusAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} {llm_result.containment_advice}"
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="map_blast_radius",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="map_blast_radius",
        input_summary=(f"Mapping blast radius for {len(assessments)} assessments"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="blast_radius_mapper",
    )

    return {
        "blast_radius_mappings": [m.model_dump() for m in mappings],
        "stage": SCREStage.RECOMMEND_MITIGATIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "map_blast_radius",
    }


# ---- Node: recommend_mitigations ----


async def recommend_mitigations(
    state: SupplyChainRiskEngineState,
) -> dict[str, Any]:
    """Generate mitigation recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments = [RiskAssessment.model_validate(a) for a in state.risk_assessments]
    mappings = [BlastRadiusMapping.model_validate(m) for m in state.blast_radius_mappings]

    logger.info(
        "scre_recommending_mitigations",
        request_id=state.request_id,
        assessment_count=len(assessments),
    )

    recs = await toolkit.recommend_mitigations(
        assessments,
        mappings,
    )
    automated = sum(1 for r in recs if r.automated)

    output_summary = f"Generated {len(recs)} recommendations. {automated} automatable."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "assessments": len(assessments),
                "recommendations": len(recs),
                "automated": automated,
                "priorities": [r.priority for r in recs],
            },
            default=str,
        )
        llm_result = cast(
            MitigationAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_RECOMMEND_MITIGATIONS,
                user_prompt=(f"Mitigation results:\n{ctx}"),
                schema=MitigationAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} {len(recs)} recommendations."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="recommend_mitigations",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="recommend_mitigations",
        input_summary=(f"Recommending mitigations for {len(assessments)} assessments"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="mitigation_recommender",
    )

    return {
        "mitigations": [r.model_dump() for r in recs],
        "stage": SCREStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "recommend_mitigations",
    }


# ---- Node: generate_report ----


async def generate_report(
    state: SupplyChainRiskEngineState,
) -> dict[str, Any]:
    """Final reporting node -- summarize the SCRE cycle."""
    start = datetime.now(UTC)

    session_duration_ms = 0
    if state.session_start:
        session_duration_ms = _elapsed_ms(state.session_start)

    output_summary = (
        f"SCRE cycle complete. "
        f"{state.dependency_count} dependencies, "
        f"{state.vulnerability_count} vulnerabilities, "
        f"{state.critical_count} critical, "
        f"{len(state.blast_radius_mappings)} blast mapped, "
        f"{len(state.mitigations)} mitigations. "
        f"Duration: {session_duration_ms}ms."
    )

    logger.info(
        "scre_report",
        request_id=state.request_id,
        summary=output_summary,
    )

    report = {
        "request_id": state.request_id,
        "tenant_id": state.tenant_id,
        "dependencies_inventoried": state.dependency_count,
        "vulnerabilities_found": state.vulnerability_count,
        "critical_vulnerabilities": state.critical_count,
        "blast_radius_mapped": len(state.blast_radius_mappings),
        "mitigations_generated": len(state.mitigations),
        "duration_ms": session_duration_ms,
        "summary": output_summary,
    }

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary=("Generating final supply chain risk report"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": session_duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
