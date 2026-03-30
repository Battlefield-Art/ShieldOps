"""Compliance Workflow Agent — Node function implementations."""

from __future__ import annotations

from typing import Any

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    ComplianceControl,
    ComplianceGap,
    ControlStatus,
    CWStage,
    EvidenceItem,
    FrameworkMapping,
)
from .prompts import (
    SYSTEM_ASSESS_GAPS,
    SYSTEM_COLLECT_EVIDENCE,
    SYSTEM_GENERATE_REMEDIATION,
    SYSTEM_IDENTIFY_FRAMEWORKS,
    SYSTEM_MAP_CONTROLS,
    SYSTEM_REPORT,
    LLMComplianceReport,
    LLMControlMapping,
    LLMFrameworkAnalysis,
    LLMGapAssessment,
    LLMRemediationPlan,
)
from .tools import ComplianceWorkflowToolkit

logger = structlog.get_logger()


# ── Node 1: Identify Frameworks ───────────────────


async def identify_frameworks(
    state: dict[str, Any],
    toolkit: ComplianceWorkflowToolkit,
) -> dict[str, Any]:
    """Identify applicable compliance frameworks."""
    logger.info(
        "compliance_workflow.node.identify_frameworks",
    )
    tenant_id = state.get("tenant_id", "default")

    mappings = await toolkit.identify_frameworks(
        tenant_id,
    )
    mapping_dicts = [m.model_dump() for m in mappings]

    # LLM enrichment
    try:
        analysis: LLMFrameworkAnalysis = await llm_structured(
            system_prompt=SYSTEM_IDENTIFY_FRAMEWORKS,
            user_prompt=(
                f"Tenant: {tenant_id}. "
                f"Identified frameworks: "
                f"{[m.framework.value for m in mappings]}"
                f". Validate applicability."
            ),
            response_model=LLMFrameworkAnalysis,
        )
        reasoning = f"Frameworks identified: {analysis.applicable_frameworks}. {analysis.rationale}"
    except Exception:
        logger.warning(
            "compliance_workflow.identify.llm_fallback",
        )
        reasoning = f"Identified {len(mappings)} frameworks for tenant {tenant_id}"

    return {
        "stage": CWStage.MAP_CONTROLS.value,
        "framework_mappings": mapping_dicts,
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


# ── Node 2: Map Controls ──────────────────────────


async def map_controls(
    state: dict[str, Any],
    toolkit: ComplianceWorkflowToolkit,
) -> dict[str, Any]:
    """Map controls for each identified framework."""
    logger.info("compliance_workflow.node.map_controls")
    raw_mappings = state.get("framework_mappings", [])
    mappings = [FrameworkMapping(**m) for m in raw_mappings]

    controls = await toolkit.map_controls(mappings)
    control_dicts = [c.model_dump() for c in controls]

    # LLM enrichment
    try:
        analysis: LLMControlMapping = await llm_structured(
            system_prompt=SYSTEM_MAP_CONTROLS,
            user_prompt=(
                f"Mapped {len(controls)} controls"
                f" across {len(mappings)} frameworks."
                f" Analyze coverage and overlaps."
            ),
            response_model=LLMControlMapping,
        )
        reasoning = (
            f"Mapped {len(controls)} controls. "
            f"Confidence: "
            f"{analysis.mapping_confidence:.0%}. "
            f"Overlaps: "
            f"{len(analysis.cross_framework_overlaps)}"
        )
    except Exception:
        logger.warning(
            "compliance_workflow.map.llm_fallback",
        )
        reasoning = f"Mapped {len(controls)} controls"

    return {
        "stage": CWStage.COLLECT_EVIDENCE.value,
        "controls": control_dicts,
        "total_controls": len(controls),
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


# ── Node 3: Collect Evidence ──────────────────────


async def collect_evidence(
    state: dict[str, Any],
    toolkit: ComplianceWorkflowToolkit,
) -> dict[str, Any]:
    """Collect evidence for each mapped control."""
    logger.info(
        "compliance_workflow.node.collect_evidence",
    )
    raw_controls = state.get("controls", [])
    controls = [ComplianceControl(**c) for c in raw_controls]

    evidence = await toolkit.collect_evidence(controls)
    evidence_dicts = [e.model_dump() for e in evidence]
    valid_count = sum(1 for e in evidence if e.valid)

    # LLM enrichment
    try:

        class _LLMEvidenceSummary(BaseModel):
            coverage_assessment: str = ""
            stale_evidence_risk: str = ""

        summary = await llm_structured(
            system_prompt=SYSTEM_COLLECT_EVIDENCE,
            user_prompt=(
                f"Collected {len(evidence)} evidence"
                f" items for {len(controls)} controls."
                f" Valid: {valid_count}."
                f" Assess evidence coverage."
            ),
            response_model=_LLMEvidenceSummary,
        )
        reasoning = (
            f"Collected {len(evidence)} evidence "
            f"items ({valid_count} valid). "
            f"{summary.coverage_assessment}"
        )
    except Exception:
        logger.warning(
            "compliance_workflow.evidence.llm_fallback",
        )
        reasoning = f"Collected {len(evidence)} evidence items ({valid_count} valid)"

    return {
        "stage": CWStage.ASSESS_GAPS.value,
        "evidence": evidence_dicts,
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


# ── Node 4: Assess Gaps ───────────────────────────


async def assess_gaps(
    state: dict[str, Any],
    toolkit: ComplianceWorkflowToolkit,
) -> dict[str, Any]:
    """Assess compliance gaps."""
    logger.info("compliance_workflow.node.assess_gaps")
    raw_controls = state.get("controls", [])
    raw_evidence = state.get("evidence", [])
    controls = [ComplianceControl(**c) for c in raw_controls]
    evidence = [EvidenceItem(**e) for e in raw_evidence]

    gaps = await toolkit.assess_gaps(controls, evidence)
    gap_dicts = [g.model_dump() for g in gaps]

    # Compute compliance score
    total = len(controls)
    compliant = sum(1 for c in controls if c.status == ControlStatus.COMPLIANT)
    score = (compliant / total * 100.0) if total > 0 else 0.0

    # LLM enrichment
    try:
        analysis: LLMGapAssessment = await llm_structured(
            system_prompt=SYSTEM_ASSESS_GAPS,
            user_prompt=(
                f"Found {len(gaps)} gaps across "
                f"{total} controls. "
                f"Score: {score:.1f}%. "
                f"Analyze risk exposure."
            ),
            response_model=LLMGapAssessment,
        )
        reasoning = f"Score: {score:.1f}%. Gaps: {len(gaps)}. Risk: {analysis.risk_summary}"
    except Exception:
        logger.warning(
            "compliance_workflow.gaps.llm_fallback",
        )
        reasoning = f"Score: {score:.1f}%. Gaps: {len(gaps)}"

    return {
        "stage": CWStage.GENERATE_REMEDIATION.value,
        "gaps": gap_dicts,
        "gaps_found": len(gaps),
        "compliance_score": round(score, 2),
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


# ── Node 5: Generate Remediation ──────────────────


async def generate_remediation(
    state: dict[str, Any],
    toolkit: ComplianceWorkflowToolkit,
) -> dict[str, Any]:
    """Generate remediation actions for gaps."""
    logger.info(
        "compliance_workflow.node.generate_remediation",
    )
    raw_gaps = state.get("gaps", [])
    gaps = [ComplianceGap(**g) for g in raw_gaps]

    actions = await toolkit.generate_remediation(gaps)
    action_dicts = [a.model_dump() for a in actions]

    # LLM enrichment
    try:
        plan: LLMRemediationPlan = await llm_structured(
            system_prompt=SYSTEM_GENERATE_REMEDIATION,
            user_prompt=(
                f"Generated {len(actions)}"
                f" remediation actions for"
                f" {len(gaps)} gaps."
                f" Identify quick wins."
            ),
            response_model=LLMRemediationPlan,
        )
        reasoning = (
            f"Remediation: {len(actions)} actions. "
            f"Quick wins: {len(plan.quick_wins)}. "
            f"Risk reduction: "
            f"{plan.risk_reduction_estimate:.0%}"
        )
    except Exception:
        logger.warning(
            "compliance_workflow.remediation.llm_fallback",
        )
        reasoning = f"Generated {len(actions)} remediation actions"

    return {
        "stage": CWStage.REPORT.value,
        "remediation_actions": action_dicts,
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }


# ── Node 6: Report ────────────────────────────────


async def generate_report(
    state: dict[str, Any],
    toolkit: ComplianceWorkflowToolkit,
) -> dict[str, Any]:
    """Generate the final compliance report."""
    logger.info("compliance_workflow.node.report")
    score = state.get("compliance_score", 0.0)
    gaps_found = state.get("gaps_found", 0)
    total = state.get("total_controls", 0)
    frameworks = state.get("framework_mappings", [])
    remediation = state.get("remediation_actions", [])

    # LLM enrichment
    executive_summary = ""
    top_risks: list[str] = []
    try:
        report_llm: LLMComplianceReport = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(
                f"Score: {score:.1f}%. "
                f"Controls: {total}. "
                f"Gaps: {gaps_found}. "
                f"Frameworks: {len(frameworks)}. "
                f"Actions: {len(remediation)}. "
                f"Generate executive report."
            ),
            response_model=LLMComplianceReport,
        )
        executive_summary = report_llm.executive_summary
        top_risks = report_llm.top_risks
    except Exception:
        logger.warning(
            "compliance_workflow.report.llm_fallback",
        )
        executive_summary = (
            f"Compliance assessment complete. Score: {score:.1f}% across {total} controls."
        )

    report = {
        "executive_summary": executive_summary,
        "compliance_score": score,
        "total_controls": total,
        "gaps_found": gaps_found,
        "frameworks_assessed": len(frameworks),
        "remediation_actions": len(remediation),
        "top_risks": top_risks,
        "status": ("passing" if score >= 80.0 else "needs_attention"),
    }

    reasoning = f"Report generated. Status: {report['status']}. Score: {score:.1f}%"

    return {
        "stage": CWStage.REPORT.value,
        "report": report,
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning]),
    }
