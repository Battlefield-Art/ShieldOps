"""AI Compliance Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    AISystemRecord,
    ComplianceRequirement,
    ComplianceStage,
    ControlAssessment,
)
from .tools import AIComplianceToolkit

logger = structlog.get_logger()

# Module-level toolkit reference for node functions
_toolkit: AIComplianceToolkit | None = None


def _get_toolkit() -> AIComplianceToolkit:
    """Get the module-level toolkit, creating a default if needed."""
    global _toolkit
    if _toolkit is None:
        _toolkit = AIComplianceToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def collect_inventory(state: dict[str, Any], toolkit: AIComplianceToolkit) -> dict[str, Any]:
    """Collect AI system inventory for compliance assessment."""
    logger.info("ai_compliance.node.collect_inventory")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    systems = await toolkit.collect_inventory(tenant_id)
    systems_data = [s.model_dump() for s in systems]

    return {
        "stage": ComplianceStage.CLASSIFY_RISK.value,
        "systems": systems_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Collected {len(systems)} AI systems for tenant '{tenant_id}'"],
    }


async def classify_risk_levels(
    state: dict[str, Any], toolkit: AIComplianceToolkit
) -> dict[str, Any]:
    """Classify risk levels for AI systems per EU AI Act tiers."""
    logger.info("ai_compliance.node.classify_risk_levels")
    state = _to_dict(state)

    raw_systems = state.get("systems", [])
    systems = [AISystemRecord(**s) for s in raw_systems]

    classified = toolkit.classify_risk(systems)
    classified_data = [s.model_dump() for s in classified]

    classifications = {s.system_id: s.risk_classification.value for s in classified}

    reasoning_note = f"Classified {len(classified)} systems: " + ", ".join(
        f"{k}={v}" for k, v in classifications.items()
    )

    # LLM enhancement: deeper risk classification analysis
    try:
        from .prompts import SYSTEM_CLASSIFY, RiskClassificationResult

        classify_context = json.dumps(
            {
                "total_systems": len(classified),
                "systems_summary": [
                    {
                        "system_id": s.system_id,
                        "name": s.name,
                        "domain": s.domain,
                        "purpose": s.purpose,
                        "model_type": s.model_type,
                        "data_categories": s.data_categories,
                        "initial_classification": s.risk_classification.value,
                    }
                    for s in classified[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            RiskClassificationResult,
            await llm_structured(
                system_prompt=SYSTEM_CLASSIFY,
                user_prompt=f"AI system classification context:\n{classify_context}",
                schema=RiskClassificationResult,
            ),
        )
        logger.info("llm_enhanced", agent="ai_compliance", node="classify_risk_levels")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="ai_compliance", node="classify_risk_levels")

    return {
        "stage": ComplianceStage.ASSESS_REQUIREMENTS.value,
        "systems": classified_data,
        "classifications": classifications,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def assess_requirements(
    state: dict[str, Any], toolkit: AIComplianceToolkit
) -> dict[str, Any]:
    """Determine applicable compliance requirements."""
    logger.info("ai_compliance.node.assess_requirements")
    state = _to_dict(state)

    raw_systems = state.get("systems", [])
    systems = [AISystemRecord(**s) for s in raw_systems]
    frameworks = state.get("frameworks", ["eu_ai_act", "nist_ai_rmf", "iso_42001"])

    requirements = toolkit.assess_requirements(systems, frameworks)
    requirements_data = [r.model_dump() for r in requirements]

    return {
        "stage": ComplianceStage.EVALUATE_CONTROLS.value,
        "requirements": requirements_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Identified {len(requirements)} applicable requirements across "
            f"{len(frameworks)} frameworks"
        ],
    }


async def evaluate_controls(state: dict[str, Any], toolkit: AIComplianceToolkit) -> dict[str, Any]:
    """Evaluate controls against compliance requirements."""
    logger.info("ai_compliance.node.evaluate_controls")
    state = _to_dict(state)

    raw_systems = state.get("systems", [])
    systems = [AISystemRecord(**s) for s in raw_systems]

    raw_requirements = state.get("requirements", [])
    requirements = [ComplianceRequirement(**r) for r in raw_requirements]

    assessments = toolkit.evaluate_controls(systems, requirements)
    assessments_data = [a.model_dump() for a in assessments]

    # Calculate per-framework compliance scores
    compliance_scores = toolkit.calculate_compliance_scores(assessments)

    # LLM enhancement: deeper control evaluation
    try:
        from .prompts import SYSTEM_ASSESS

        assess_context = json.dumps(
            {
                "total_assessments": len(assessments),
                "compliance_scores": compliance_scores,
                "gap_count": sum(1 for a in assessments if a.status.value == "missing"),
                "partial_count": sum(1 for a in assessments if a.status.value == "partial"),
            },
            default=str,
        )
        from .prompts import ComplianceReportResult

        cast(
            ComplianceReportResult,
            await llm_structured(
                system_prompt=SYSTEM_ASSESS,
                user_prompt=f"Control evaluation context:\n{assess_context}",
                schema=ComplianceReportResult,
            ),
        )
        logger.info("llm_enhanced", agent="ai_compliance", node="evaluate_controls")
    except Exception:
        logger.debug("llm_fallback", agent="ai_compliance", node="evaluate_controls")

    return {
        "stage": ComplianceStage.GENERATE_EVIDENCE.value,
        "assessments": assessments_data,
        "compliance_scores": compliance_scores,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Evaluated {len(assessments)} controls — scores: {compliance_scores}"],
    }


async def generate_evidence(state: dict[str, Any], toolkit: AIComplianceToolkit) -> dict[str, Any]:
    """Generate evidence packages for compliance assessments."""
    logger.info("ai_compliance.node.generate_evidence")
    state = _to_dict(state)

    raw_systems = state.get("systems", [])
    systems = [AISystemRecord(**s) for s in raw_systems]

    raw_assessments = state.get("assessments", [])
    assessments = [ControlAssessment(**a) for a in raw_assessments]

    evidence = await toolkit.generate_evidence(systems, assessments)
    evidence_data = [e.model_dump() for e in evidence]

    return {
        "stage": ComplianceStage.REPORT.value,
        "evidence": evidence_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Generated {len(evidence)} evidence packages"],
    }


async def generate_report(state: dict[str, Any], toolkit: AIComplianceToolkit) -> dict[str, Any]:
    """Generate final compliance report with LLM-enhanced analysis."""
    logger.info("ai_compliance.node.generate_report")
    state = _to_dict(state)

    compliance_scores = state.get("compliance_scores", {})
    raw_assessments = state.get("assessments", [])
    assessments = [ControlAssessment(**a) for a in raw_assessments]

    gap_count = sum(1 for a in assessments if a.status.value == "missing")
    partial_count = sum(1 for a in assessments if a.status.value == "partial")
    implemented_count = sum(1 for a in assessments if a.status.value == "implemented")

    reasoning_note = (
        f"Compliance report: {implemented_count} implemented, "
        f"{partial_count} partial, {gap_count} gaps. "
        f"Framework scores: {compliance_scores}"
    )

    # LLM enhancement: generate executive summary
    try:
        from .prompts import SYSTEM_REPORT, ComplianceReportResult

        report_context = json.dumps(
            {
                "compliance_scores": compliance_scores,
                "total_assessments": len(assessments),
                "implemented": implemented_count,
                "partial": partial_count,
                "gaps": gap_count,
                "systems_assessed": len(state.get("systems", [])),
                "frameworks": state.get("frameworks", []),
                "classifications": state.get("classifications", {}),
            },
            default=str,
        )
        llm_result = cast(
            ComplianceReportResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Compliance assessment results:\n{report_context}",
                schema=ComplianceReportResult,
            ),
        )
        logger.info("llm_enhanced", agent="ai_compliance", node="generate_report")
        reasoning_note = f"{llm_result.executive_summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="ai_compliance", node="generate_report")

    return {
        "stage": ComplianceStage.REPORT.value,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }
