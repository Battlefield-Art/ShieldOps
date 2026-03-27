"""Compliance Gap Analyzer Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any

import structlog

from shieldops.utils.llm import llm_structured

from .models import (
    ComplianceGap,
    ComplianceStage,
    Framework,
    FrameworkMapping,
    SecurityControl,
)
from .prompts import (
    SYSTEM_MAP_FRAMEWORKS,
    SYSTEM_REMEDIATION,
    SYSTEM_REPORT,
    ComplianceReportOutput,
    FrameworkMappingOutput,
    RemediationPlanOutput,
)
from .tools import ComplianceGapAnalyzerToolkit

logger = structlog.get_logger()


async def inventory_controls(
    state: dict[str, Any],
    toolkit: ComplianceGapAnalyzerToolkit,
) -> dict[str, Any]:
    """Collect security controls inventory."""
    logger.info(
        "compliance_gap.node.inventory_controls",
    )

    tenant_id = state.get("tenant_id", "")
    controls = await toolkit.inventory_controls(
        tenant_id,
    )
    data = [c.model_dump() for c in controls]

    return {
        "current_stage": (ComplianceStage.INVENTORY_CONTROLS.value),
        "controls_inventoried": data,
        "reasoning_chain": (
            state.get("reasoning_chain", []) + [f"Inventoried {len(controls)} security controls"]
        ),
    }


async def map_to_frameworks(
    state: dict[str, Any],
    toolkit: ComplianceGapAnalyzerToolkit,
) -> dict[str, Any]:
    """Map controls to compliance frameworks."""
    logger.info(
        "compliance_gap.node.map_to_frameworks",
    )

    raw_controls = state.get(
        "controls_inventoried",
        [],
    )
    controls = [SecurityControl(**c) for c in raw_controls]

    raw_fws = state.get(
        "frameworks",
        ["soc2", "hipaa", "nist_csf"],
    )
    frameworks = [Framework(f) for f in raw_fws]

    mappings = await toolkit.map_to_frameworks(
        controls,
        frameworks,
    )

    # LLM enhancement for mapping quality
    for mapping in mappings[:5]:
        if mapping.gap_description:
            try:
                ctrl = next(
                    (c for c in controls if c.id == mapping.control_id),
                    None,
                )
                result = await llm_structured(
                    system_prompt=(SYSTEM_MAP_FRAMEWORKS),
                    user_prompt=(
                        f"Control: "
                        f"{ctrl.name if ctrl else 'N/A'}\n"
                        f"Framework: {mapping.framework}\n"
                        f"Requirement: "
                        f"{mapping.requirement_name}"
                    ),
                    output_schema=(FrameworkMappingOutput),
                )
                mapping.gap_description = result.gap_description
            except Exception:
                logger.debug(
                    "compliance_gap.llm_map_fallback",
                )

    data = [m.model_dump() for m in mappings]

    return {
        "current_stage": (ComplianceStage.MAP_TO_FRAMEWORKS.value),
        "mappings": data,
        "reasoning_chain": (
            state.get("reasoning_chain", [])
            + [f"Mapped controls to {len(frameworks)} frameworks ({len(mappings)} mappings)"]
        ),
    }


async def assess_coverage(
    state: dict[str, Any],
    toolkit: ComplianceGapAnalyzerToolkit,
) -> dict[str, Any]:
    """Assess coverage per framework."""
    logger.info(
        "compliance_gap.node.assess_coverage",
    )

    raw = state.get("mappings", [])
    mappings = [FrameworkMapping(**m) for m in raw]
    assessments = await toolkit.assess_coverage(
        mappings,
    )
    data = [a.model_dump() for a in assessments]

    # Calculate overall compliance
    total_pct = sum(a.coverage_pct for a in assessments) / len(assessments) if assessments else 0.0
    fw_scores = {a.framework.value: a.coverage_pct for a in assessments}

    return {
        "current_stage": (ComplianceStage.ASSESS_COVERAGE.value),
        "coverage_assessments": data,
        "overall_compliance_pct": round(total_pct, 1),
        "framework_scores": fw_scores,
        "reasoning_chain": (
            state.get("reasoning_chain", []) + [f"Overall compliance: {round(total_pct, 1)}%"]
        ),
    }


async def identify_gaps(
    state: dict[str, Any],
    toolkit: ComplianceGapAnalyzerToolkit,
) -> dict[str, Any]:
    """Identify compliance gaps."""
    logger.info("compliance_gap.node.identify_gaps")

    raw = state.get("mappings", [])
    mappings = [FrameworkMapping(**m) for m in raw]
    gaps = await toolkit.identify_gaps(mappings)
    data = [g.model_dump() for g in gaps]

    return {
        "current_stage": (ComplianceStage.IDENTIFY_GAPS.value),
        "gaps": data,
        "reasoning_chain": (
            state.get("reasoning_chain", []) + [f"Identified {len(gaps)} compliance gaps"]
        ),
    }


async def generate_remediation_plan(
    state: dict[str, Any],
    toolkit: ComplianceGapAnalyzerToolkit,
) -> dict[str, Any]:
    """Generate remediation plans for gaps."""
    logger.info(
        "compliance_gap.node.remediation_plan",
    )

    raw = state.get("gaps", [])
    gaps = [ComplianceGap(**g) for g in raw]
    plans = await toolkit.generate_remediation_plans(
        gaps,
    )

    # LLM enhancement for plan quality
    for plan in plans[:5]:
        try:
            gap = next(
                (g for g in gaps if g.requirement_id == plan.requirement_id),
                None,
            )
            result = await llm_structured(
                system_prompt=SYSTEM_REMEDIATION,
                user_prompt=(
                    f"Gap: {gap.requirement_name if gap else 'N/A'}\n"
                    f"Framework: {plan.framework}\n"
                    f"Status: {gap.current_status if gap else 'missing'}"
                ),
                output_schema=RemediationPlanOutput,
            )
            plan.action_items = result.action_items
            plan.timeline = result.timeline
            plan.estimated_cost = result.estimated_cost
            plan.priority = result.priority
        except Exception:
            logger.debug(
                "compliance_gap.llm_remediation_fb",
            )

    data = [p.model_dump() for p in plans]

    return {
        "current_stage": (ComplianceStage.GENERATE_REMEDIATION_PLAN.value),
        "remediation_plans": data,
        "reasoning_chain": (
            state.get("reasoning_chain", []) + [f"Generated {len(plans)} remediation plans"]
        ),
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: ComplianceGapAnalyzerToolkit,
) -> dict[str, Any]:
    """Generate final compliance report."""
    logger.info("compliance_gap.node.generate_report")

    try:
        context = json.dumps(
            {
                "overall_compliance_pct": state.get(
                    "overall_compliance_pct",
                    0,
                ),
                "framework_scores": state.get(
                    "framework_scores",
                    {},
                ),
                "gap_count": len(
                    state.get("gaps", []),
                ),
                "plan_count": len(
                    state.get(
                        "remediation_plans",
                        [],
                    ),
                ),
            },
            default=str,
        )
        result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Compliance analysis:\n{context}"),
            output_schema=ComplianceReportOutput,
        )
        summary = result.executive_summary
    except Exception:
        logger.debug(
            "compliance_gap.llm_report_fallback",
        )
        pct = state.get("overall_compliance_pct", 0)
        gaps = len(state.get("gaps", []))
        summary = f"Compliance at {pct}%. {gaps} gaps identified."

    return {
        "current_stage": (ComplianceStage.REPORT.value),
        "reasoning_chain": (state.get("reasoning_chain", []) + [f"Report: {summary[:120]}"]),
    }
