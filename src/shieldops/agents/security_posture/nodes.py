"""Security Posture Manager Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    DomainAssessment,
    PostureDomain,
    PostureGap,
    PostureStage,
)
from .tools import SecurityPostureToolkit

logger = structlog.get_logger()

# Module-level toolkit reference for node functions
_toolkit: SecurityPostureToolkit | None = None


def set_toolkit(toolkit: SecurityPostureToolkit) -> None:
    """Set the module-level toolkit for node functions."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> SecurityPostureToolkit:
    """Get the module-level toolkit, creating a default if needed."""
    global _toolkit
    if _toolkit is None:
        _toolkit = SecurityPostureToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def assess_domains(state: dict[str, Any], toolkit: SecurityPostureToolkit) -> dict[str, Any]:
    """Assess all five security domains and collect findings."""
    logger.info("security_posture.node.assess_domains")
    state = _to_dict(state)

    assessments: list[dict[str, Any]] = []
    for domain in PostureDomain:
        assessment = await toolkit.assess_domain(domain)
        assessments.append(assessment.model_dump())

    return {
        "stage": PostureStage.SCORE.value,
        "assessments": assessments,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Assessed {len(assessments)} security domains"],
    }


async def identify_gaps(state: dict[str, Any], toolkit: SecurityPostureToolkit) -> dict[str, Any]:
    """Identify gaps between current posture and target state."""
    logger.info("security_posture.node.identify_gaps")
    state = _to_dict(state)

    raw_assessments = state.get("assessments", [])
    assessments = [DomainAssessment(**a) for a in raw_assessments]

    gaps = await toolkit.identify_gaps(assessments)
    gaps_data = [g.model_dump() for g in gaps]

    return {
        "stage": PostureStage.PRIORITIZE.value,
        "gaps": gaps_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Identified {len(gaps)} posture gaps across all domains"],
    }


async def prioritize_remediation(
    state: dict[str, Any], toolkit: SecurityPostureToolkit
) -> dict[str, Any]:
    """Prioritize gaps by impact-to-effort ratio."""
    logger.info("security_posture.node.prioritize_remediation")
    state = _to_dict(state)

    raw_gaps = state.get("gaps", [])
    gaps = [PostureGap(**g) for g in raw_gaps]

    prioritized = toolkit.prioritize_gaps(gaps)
    prioritized_data = [g.model_dump() for g in prioritized]

    # Calculate overall score from assessments
    raw_assessments = state.get("assessments", [])
    assessments = [DomainAssessment(**a) for a in raw_assessments]
    overall_score = 0.0
    if assessments:
        overall_score = round(sum(a.score for a in assessments) / len(assessments), 1)

    reasoning_note = f"Prioritized {len(prioritized)} gaps, overall score: {overall_score}"

    # LLM enhancement: intelligent prioritization reasoning
    try:
        from .prompts import SYSTEM_PRIORITIZE, PrioritizationResult

        prioritize_context = json.dumps(
            {
                "overall_score": overall_score,
                "total_gaps": len(prioritized),
                "gaps_summary": [
                    {
                        "domain": g.domain.value if hasattr(g.domain, "value") else str(g.domain),
                        "risk_category": g.risk_category,  # type: ignore[attr-defined]
                        "effort_hours": g.effort_hours,
                    }
                    for g in prioritized[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            PrioritizationResult,
            await llm_structured(
                system_prompt=SYSTEM_PRIORITIZE,
                user_prompt=f"Prioritization context:\n{prioritize_context}",
                schema=PrioritizationResult,
            ),
        )
        logger.info("llm_enhanced", agent="security_posture", node="prioritize_remediation")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="security_posture", node="prioritize_remediation")

    return {
        "stage": PostureStage.RECOMMEND.value,
        "gaps": prioritized_data,
        "overall_score": overall_score,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def generate_report(state: dict[str, Any], toolkit: SecurityPostureToolkit) -> dict[str, Any]:
    """Generate the unified security posture report."""
    logger.info("security_posture.node.generate_report")
    state = _to_dict(state)

    raw_assessments = state.get("assessments", [])
    raw_gaps = state.get("gaps", [])
    assessments = [DomainAssessment(**a) for a in raw_assessments]
    gaps = [PostureGap(**g) for g in raw_gaps]

    report = toolkit.generate_posture_report(assessments, gaps)
    report_data = report.model_dump()

    return {
        "stage": PostureStage.RECOMMEND.value,
        "report": report_data,
        "overall_score": report.overall_score,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Generated posture report: score={report.overall_score}, "
            f"trend={report.trend}, {len(report.recommendations)} recommendations"
        ],
    }
