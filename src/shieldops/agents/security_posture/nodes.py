"""Security Posture Manager Agent — Node function implementations."""

from __future__ import annotations

from typing import Any

import structlog
from pydantic import BaseModel

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
    return state


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

    return {
        "stage": PostureStage.RECOMMEND.value,
        "gaps": prioritized_data,
        "overall_score": overall_score,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Prioritized {len(prioritized)} gaps, overall score: {overall_score}"],
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
