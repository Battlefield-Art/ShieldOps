"""Node implementations for the Credential Hygiene Auditor LangGraph workflow.

Each node is an async function that:
1. Queries credential systems via the toolkit
2. Uses the LLM to analyze and reason about data
3. Updates the CHA state with findings
4. Records its reasoning step in the audit trail
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.credential_hygiene_auditor.models import (
    CHAStage,
    CredentialHygieneAuditorState,
    CredentialRecord,
    CredentialRiskScore,
    HygieneAssessment,
    HygieneStatus,
    HygieneViolation,
    ReasoningStep,
)
from shieldops.agents.credential_hygiene_auditor.prompts import (
    SYSTEM_ASSESS_HYGIENE,
    SYSTEM_DETECT_VIOLATIONS,
    SYSTEM_INVENTORY_CREDENTIALS,
    SYSTEM_RECOMMEND_FIXES,
    SYSTEM_SCORE_RISK,
    CredentialInventoryAnalysis,
    HygieneAssessmentAnalysis,
    RemediationAnalysis,
    RiskScoringAnalysis,
    ViolationDetectionAnalysis,
)
from shieldops.agents.credential_hygiene_auditor.tools import (
    CredentialHygieneAuditorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

# Module-level toolkit, set by runner at startup.
_toolkit: CredentialHygieneAuditorToolkit | None = None


def set_toolkit(
    toolkit: CredentialHygieneAuditorToolkit,
) -> None:
    """Configure toolkit used by all nodes."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> CredentialHygieneAuditorToolkit:
    if _toolkit is None:
        return CredentialHygieneAuditorToolkit()
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


# ---- Node: inventory_credentials ----


async def inventory_credentials(
    state: CredentialHygieneAuditorState,
) -> dict[str, Any]:
    """Inventory credentials across the organization."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "cha_inventorying_credentials",
        request_id=state.request_id,
    )

    scope = state.config.get("scope")
    records = await toolkit.inventory_credentials(
        tenant_id=state.tenant_id,
        scope=scope,
    )

    types_found = list({r.credential_type.value for r in records})
    output_summary = f"Inventoried {len(records)} credentials across {len(types_found)} types."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "credentials_found": len(records),
                "types": types_found,
                "owners": list({r.owner for r in records}),
                "systems": list({r.system for r in records}),
            },
            default=str,
        )
        llm_result = cast(
            CredentialInventoryAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_INVENTORY_CREDENTIALS,
                user_prompt=(f"Credential inventory results:\n{ctx}"),
                schema=CredentialInventoryAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} {len(records)} credentials."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="inventory_credentials",
        )

    step = ReasoningStep(
        step_number=1,
        action="inventory_credentials",
        input_summary="Inventorying credentials across org",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="credential_inventorier",
    )

    return {
        "credentials": [r.model_dump() for r in records],
        "credential_count": len(records),
        "stage": CHAStage.ASSESS_HYGIENE,
        "session_start": start,
        "reasoning_chain": [step],
        "current_step": "inventory_credentials",
    }


# ---- Node: assess_hygiene ----


async def assess_hygiene(
    state: CredentialHygieneAuditorState,
) -> dict[str, Any]:
    """Assess hygiene status of inventoried credentials."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    records = [CredentialRecord.model_validate(c) for c in state.credentials]

    logger.info(
        "cha_assessing_hygiene",
        request_id=state.request_id,
        credential_count=len(records),
    )

    assessments = await toolkit.assess_hygiene(records)
    compliant = sum(1 for a in assessments if a.status == HygieneStatus.COMPLIANT)

    output_summary = f"Assessed {len(assessments)} credentials. {compliant} compliant."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "credentials": len(records),
                "assessments": len(assessments),
                "compliant": compliant,
                "statuses": [a.status.value for a in assessments],
            },
            default=str,
        )
        llm_result = cast(
            HygieneAssessmentAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_ASSESS_HYGIENE,
                user_prompt=(f"Hygiene assessment results:\n{ctx}"),
                schema=HygieneAssessmentAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Quality: {llm_result.assessment_quality}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_hygiene",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="assess_hygiene",
        input_summary=(f"Assessing hygiene for {len(records)} credentials"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="hygiene_assessor",
    )

    return {
        "assessments": [a.model_dump() for a in assessments],
        "compliant_count": compliant,
        "stage": CHAStage.DETECT_VIOLATIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_hygiene",
    }


# ---- Node: detect_violations ----


async def detect_violations(
    state: CredentialHygieneAuditorState,
) -> dict[str, Any]:
    """Detect credential hygiene violations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments = [HygieneAssessment.model_validate(a) for a in state.assessments]

    logger.info(
        "cha_detecting_violations",
        request_id=state.request_id,
        assessment_count=len(assessments),
    )

    violations = await toolkit.detect_violations(assessments)
    critical = sum(1 for v in violations if v.severity == "critical")

    output_summary = f"Detected {len(violations)} violations. {critical} critical."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "assessments": len(assessments),
                "violations": len(violations),
                "critical": critical,
                "types": [v.violation_type for v in violations],
            },
            default=str,
        )
        llm_result = cast(
            ViolationDetectionAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_DETECT_VIOLATIONS,
                user_prompt=(f"Violation detection results:\n{ctx}"),
                schema=ViolationDetectionAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Threat: {llm_result.threat_level}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_violations",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="detect_violations",
        input_summary=(f"Detecting violations from {len(assessments)} assessments"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="violation_detector",
    )

    return {
        "violations": [v.model_dump() for v in violations],
        "violation_count": len(violations),
        "stage": CHAStage.SCORE_RISK,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_violations",
    }


# ---- Node: score_risk ----


async def score_risk(
    state: CredentialHygieneAuditorState,
) -> dict[str, Any]:
    """Score risk based on violations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    violations = [HygieneViolation.model_validate(v) for v in state.violations]

    logger.info(
        "cha_scoring_risk",
        request_id=state.request_id,
        violation_count=len(violations),
    )

    scores = await toolkit.score_risk(violations)
    high_risk = sum(1 for s in scores if s.overall_score > 0.7)

    output_summary = f"Scored {len(scores)} credential groups. {high_risk} high-risk."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "violations": len(violations),
                "scores": len(scores),
                "high_risk": high_risk,
                "avg_score": round(
                    sum(s.overall_score for s in scores) / max(len(scores), 1),
                    3,
                ),
            },
            default=str,
        )
        llm_result = cast(
            RiskScoringAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_SCORE_RISK,
                user_prompt=(f"Risk scoring results:\n{ctx}"),
                schema=RiskScoringAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Risk: {llm_result.risk_assessment}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="score_risk",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="score_risk",
        input_summary=(f"Scoring risk from {len(violations)} violations"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="risk_scorer",
    )

    return {
        "risk_scores": [s.model_dump() for s in scores],
        "stage": CHAStage.RECOMMEND_FIXES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "score_risk",
    }


# ---- Node: recommend_fixes ----


async def recommend_fixes(
    state: CredentialHygieneAuditorState,
) -> dict[str, Any]:
    """Generate remediation recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    violations = [HygieneViolation.model_validate(v) for v in state.violations]
    risk_scores = [CredentialRiskScore.model_validate(s) for s in state.risk_scores]

    logger.info(
        "cha_recommending_fixes",
        request_id=state.request_id,
        violation_count=len(violations),
    )

    recs = await toolkit.recommend_fixes(
        violations,
        risk_scores,
    )

    automated = sum(1 for r in recs if r.automated)

    output_summary = f"Generated {len(recs)} recommendations. {automated} automatable."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "violations": len(violations),
                "recommendations": len(recs),
                "automated": automated,
                "priorities": [r.priority for r in recs],
            },
            default=str,
        )
        llm_result = cast(
            RemediationAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_RECOMMEND_FIXES,
                user_prompt=(f"Remediation results:\n{ctx}"),
                schema=RemediationAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} {len(recs)} recommendations."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="recommend_fixes",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="recommend_fixes",
        input_summary=(f"Recommending fixes for {len(violations)} violations"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="fix_recommender",
    )

    return {
        "recommendations": [r.model_dump() for r in recs],
        "stage": CHAStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "recommend_fixes",
    }


# ---- Node: generate_report ----


async def generate_report(
    state: CredentialHygieneAuditorState,
) -> dict[str, Any]:
    """Final reporting node -- summarize the audit cycle."""
    start = datetime.now(UTC)

    session_duration_ms = 0
    if state.session_start:
        session_duration_ms = _elapsed_ms(state.session_start)

    output_summary = (
        f"CHA cycle complete. "
        f"{state.credential_count} credentials, "
        f"{len(state.assessments)} assessed, "
        f"{state.violation_count} violations, "
        f"{state.compliant_count} compliant, "
        f"{len(state.recommendations)} recommendations. "
        f"Duration: {session_duration_ms}ms."
    )

    logger.info(
        "cha_report",
        request_id=state.request_id,
        summary=output_summary,
    )

    report = {
        "request_id": state.request_id,
        "tenant_id": state.tenant_id,
        "credentials_inventoried": state.credential_count,
        "assessments_completed": len(state.assessments),
        "violations_detected": state.violation_count,
        "compliant_credentials": state.compliant_count,
        "risk_scores_computed": len(state.risk_scores),
        "recommendations_generated": len(state.recommendations),
        "duration_ms": session_duration_ms,
        "summary": output_summary,
    }

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary=("Generating final credential hygiene report"),
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
