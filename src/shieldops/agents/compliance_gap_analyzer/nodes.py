"""Compliance Gap Analyzer Agent — Node implementations."""

from __future__ import annotations

from typing import Any

import structlog
from pydantic import BaseModel, Field

from shieldops.utils.llm import llm_structured

from .models import (
    CGAStage,
    RegulatoryDomain,
)
from .tools import ComplianceGapAnalyzerToolkit

logger = structlog.get_logger()


class _LLMGapInsight(BaseModel):
    """LLM-generated gap analysis insight."""

    critical_gaps: list[str] = Field(
        description="Most critical compliance gaps",
    )
    root_causes: list[str] = Field(
        description="Root causes of gaps",
    )
    risk_summary: str = Field(
        description="Overall risk summary",
    )


class _LLMRemediationInsight(BaseModel):
    """LLM-generated remediation guidance."""

    quick_wins: list[str] = Field(
        description="Gaps fixable quickly",
    )
    strategic_items: list[str] = Field(
        description="Long-term remediation items",
    )
    estimated_timeline: str = Field(
        description="Overall remediation timeline",
    )
    resource_requirements: str = Field(
        description="Estimated resources needed",
    )


async def scan_posture(
    state: dict[str, Any],
    toolkit: ComplianceGapAnalyzerToolkit,
) -> dict[str, Any]:
    """Scan security posture for each domain."""
    logger.info("cga.node.scan_posture")
    domains = state.get("domains", [])

    scans: list[dict[str, Any]] = []
    for domain in domains:
        domain_val = domain.value if isinstance(domain, RegulatoryDomain) else domain
        scan = await toolkit.scan_posture(domain_val)
        scans.append(scan)

    return {
        "stage": CGAStage.MAP_REQUIREMENTS.value,
        "posture_scans": scans,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [f"Scanned posture for {len(domains)} domains"],
    }


async def map_requirements(
    state: dict[str, Any],
    toolkit: ComplianceGapAnalyzerToolkit,
) -> dict[str, Any]:
    """Fetch and map regulatory requirements."""
    logger.info("cga.node.map_requirements")
    domains = state.get("domains", [])

    all_reqs: list[dict[str, Any]] = []
    for domain in domains:
        domain_val = domain.value if isinstance(domain, RegulatoryDomain) else domain
        reqs = await toolkit.fetch_requirements(
            domain_val,
        )
        all_reqs.extend(reqs)

    return {
        "stage": CGAStage.IDENTIFY_GAPS.value,
        "requirements": all_reqs,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [f"Mapped {len(all_reqs)} requirements across {len(domains)} domains"],
    }


async def identify_gaps(
    state: dict[str, Any],
    toolkit: ComplianceGapAnalyzerToolkit,
) -> dict[str, Any]:
    """Compare posture against requirements."""
    logger.info("cga.node.identify_gaps")
    posture_scans = state.get("posture_scans", [])
    requirements = state.get("requirements", [])

    all_gaps: list[dict[str, Any]] = []
    for scan in posture_scans:
        gaps = toolkit.identify_gaps(
            scan,
            requirements,
        )
        all_gaps.extend(gaps)

    # De-duplicate by requirement_id
    seen: set[str] = set()
    unique_gaps: list[dict[str, Any]] = []
    for gap in all_gaps:
        req_id = gap.get("requirement_id", "")
        if req_id not in seen:
            seen.add(req_id)
            unique_gaps.append(gap)

    critical = sum(1 for g in unique_gaps if g.get("severity") == "critical")

    # --- LLM enhancement ---
    llm_text = ""
    try:
        gap_summary = "\n".join(
            f"- {g.get('gap_id')} "
            f"[{g.get('framework')}]: "
            f"{g.get('severity')} - "
            f"{g.get('description')}"
            for g in unique_gaps[:20]
        )
        insight = await llm_structured(
            system_prompt=(
                "You are a compliance gap analyst. "
                "Analyze these gaps and identify "
                "root causes and critical risks."
            ),
            user_prompt=(
                f"Total gaps: {len(unique_gaps)}\n"
                f"Critical: {critical}\n\n"
                f"Gap details:\n{gap_summary}"
            ),
            schema=_LLMGapInsight,
        )
        if isinstance(insight, _LLMGapInsight):
            llm_text = f"LLM: {insight.risk_summary}. Root causes: {len(insight.root_causes)}."
            logger.info(
                "llm_enhanced",
                agent="cga",
                node="identify_gaps",
                critical=len(
                    insight.critical_gaps,
                ),
            )
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cga",
            node="identify_gaps",
        )

    msg = f"Identified {len(unique_gaps)} gaps, {critical} critical"
    if llm_text:
        msg += f" | {llm_text}"

    return {
        "stage": CGAStage.PRIORITIZE_RISKS.value,
        "gaps": unique_gaps,
        "total_gaps": len(unique_gaps),
        "critical_gaps": critical,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [msg],
    }


async def prioritize_risks(
    state: dict[str, Any],
    toolkit: ComplianceGapAnalyzerToolkit,
) -> dict[str, Any]:
    """Prioritize gaps by risk score."""
    logger.info("cga.node.prioritize_risks")
    gaps = state.get("gaps", [])

    priorities = toolkit.prioritize_risks(gaps)

    top_score = priorities[0]["risk_score"] if priorities else 0

    return {
        "stage": CGAStage.GENERATE_PLAN.value,
        "risk_priorities": priorities,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [f"Prioritized {len(priorities)} risks, top score: {top_score}"],
    }


async def generate_plan(
    state: dict[str, Any],
    toolkit: ComplianceGapAnalyzerToolkit,
) -> dict[str, Any]:
    """Generate remediation plans for all gaps."""
    logger.info("cga.node.generate_plan")
    gaps = state.get("gaps", [])
    priorities = state.get("risk_priorities", [])

    plans = toolkit.build_remediation_plan(
        gaps,
        priorities,
    )

    # --- LLM enhancement ---
    llm_text = ""
    try:
        plan_summary = "\n".join(
            f"- Rank {p.get('priority_rank')}: {p.get('title')} ({p.get('estimated_effort_days')}d)"
            for p in plans[:10]
        )
        insight = await llm_structured(
            system_prompt=(
                "You are a remediation planner. "
                "Analyze plans and identify quick "
                "wins vs strategic items."
            ),
            user_prompt=(f"Total plans: {len(plans)}\n\nPlan details:\n{plan_summary}"),
            schema=_LLMRemediationInsight,
        )
        if isinstance(
            insight,
            _LLMRemediationInsight,
        ):
            llm_text = f"LLM: {insight.estimated_timeline}. Quick wins: {len(insight.quick_wins)}."
            logger.info(
                "llm_enhanced",
                agent="cga",
                node="generate_plan",
                quick_wins=len(
                    insight.quick_wins,
                ),
            )
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cga",
            node="generate_plan",
        )

    total_effort = sum(p.get("estimated_effort_days", 0) for p in plans)
    msg = f"Generated {len(plans)} remediation plans, total effort: {total_effort}d"
    if llm_text:
        msg += f" | {llm_text}"

    return {
        "stage": CGAStage.REPORT.value,
        "remediation_plans": plans,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [msg],
    }


async def build_report(
    state: dict[str, Any],
    toolkit: ComplianceGapAnalyzerToolkit,
) -> dict[str, Any]:
    """Produce final compliance gap analysis report."""
    logger.info("cga.node.build_report")
    posture_scans = state.get("posture_scans", [])
    gaps = state.get("gaps", [])
    priorities = state.get("risk_priorities", [])
    plans = state.get("remediation_plans", [])

    report = toolkit.generate_report(
        posture_scans,
        gaps,
        priorities,
        plans,
    )
    score = report.get("compliance_score", 0.0)

    return {
        "stage": CGAStage.REPORT.value,
        "report": report,
        "compliance_score": score,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            f"Report: score={score}, "
            f"{report.get('total_gaps', 0)} gaps, "
            f"{report.get('remediation_plans', 0)} "
            f"plans"
        ],
    }
