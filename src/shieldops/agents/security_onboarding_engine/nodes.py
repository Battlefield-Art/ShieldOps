"""Node implementations for the Security Onboarding Engine
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random  # noqa: S311
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_onboarding_engine.models import (
    ReasoningStep,
    SecurityOnboardingEngineState,
    SOEStage,
)
from shieldops.agents.security_onboarding_engine.prompts import (
    SYSTEM_REPORT,
    SYSTEM_REQUIREMENTS,
    SYSTEM_RISK,
    SYSTEM_VALIDATE,
    OnboardingReportOutput,
    RequirementGenerationOutput,
    RiskAssessmentOutput,
    ValidationOutput,
)
from shieldops.agents.security_onboarding_engine.tools import (
    SecurityOnboardingEngineToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityOnboardingEngineToolkit | None = None


def _get_toolkit() -> SecurityOnboardingEngineToolkit:
    if _toolkit is None:
        return SecurityOnboardingEngineToolkit()
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
# Node: intake_service
# ------------------------------------------------------------------


async def intake_service(
    state: SecurityOnboardingEngineState,
) -> dict[str, Any]:
    """Intake a new service for security onboarding."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    intake = await toolkit.intake_service(
        service_name=state.service_name,
        team=state.team,
        owner=state.owner,
        environment=state.environment,
        tech_stack=state.tech_stack,
        external_facing=state.external_facing,
    )

    step = _step(
        state.reasoning_chain,
        "intake_service",
        f"Service: {state.service_name}, team={state.team}",
        "Service intake recorded",
        start,
        "intake",
    )

    return {
        "intake": intake,
        "stage": SOEStage.INTAKE_SERVICE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "intake_service",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: assess_risk_profile
# ------------------------------------------------------------------


async def assess_risk_profile(
    state: SecurityOnboardingEngineState,
) -> dict[str, Any]:
    """Assess the risk profile of the service being
    onboarded."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    risk_profile = await toolkit.assess_risk_profile(
        intake=state.intake,
        tier=state.tier.value,
        data_classification=state.data_classification.value,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "service_name": state.service_name,
                "tier": state.tier.value,
                "data_classification": state.data_classification.value,
                "tech_stack": state.tech_stack,
                "external_facing": state.external_facing,
                "environment": state.environment,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_RISK,
            user_prompt=f"Assess risk profile:\n{ctx}",
            schema=RiskAssessmentOutput,
        )
        if llm_out.threat_vectors:  # type: ignore[union-attr]
            risk_profile.update(
                {
                    "risk_score": llm_out.risk_score,  # type: ignore[union-attr]
                    "risk_level": llm_out.risk_level,  # type: ignore[union-attr]
                    "compliance_requirements": llm_out.compliance_requirements,  # type: ignore[union-attr]
                    "threat_vectors": llm_out.threat_vectors,  # type: ignore[union-attr]
                    "data_sensitivity": llm_out.data_sensitivity,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="assess_risk_profile",
            risk_level=llm_out.risk_level,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_risk_profile",
        )

    step = _step(
        state.reasoning_chain,
        "assess_risk_profile",
        f"Tier: {state.tier}, classification={state.data_classification}",
        f"Risk profile assessed: {risk_profile.get('risk_level', 'unknown')}",
        start,
        "risk_assessor",
    )

    return {
        "risk_profile": risk_profile,
        "stage": SOEStage.ASSESS_RISK_PROFILE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_risk_profile",
    }


# ------------------------------------------------------------------
# Node: generate_requirements
# ------------------------------------------------------------------


async def generate_requirements(
    state: SecurityOnboardingEngineState,
) -> dict[str, Any]:
    """Generate security requirements based on the risk
    profile."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    requirements = await toolkit.generate_requirements(
        risk_profile=state.risk_profile,
        tier=state.tier.value,
        data_classification=state.data_classification.value,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "risk_profile": state.risk_profile,
                "tier": state.tier.value,
                "data_classification": state.data_classification.value,
                "tech_stack": state.tech_stack,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REQUIREMENTS,
            user_prompt=f"Generate requirements:\n{ctx}",
            schema=RequirementGenerationOutput,
        )
        if llm_out.requirements:  # type: ignore[union-attr]
            rid = random.randint(1000, 9999)  # noqa: S311
            for i, req in enumerate(llm_out.requirements):  # type: ignore[union-attr]
                requirements.append(
                    {
                        "requirement_id": f"llm-{rid}-{i}",
                        **req,
                    }
                )
        logger.info(
            "llm_enhanced",
            node="generate_requirements",
            count=len(llm_out.requirements),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_requirements",
        )

    step = _step(
        state.reasoning_chain,
        "generate_requirements",
        f"Risk level: {state.risk_profile.get('risk_level', 'unknown')}",
        f"Generated {len(requirements)} requirements",
        start,
        "requirement_engine",
    )

    return {
        "requirements": requirements,
        "total_requirements": len(requirements),
        "stage": SOEStage.GENERATE_REQUIREMENTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "generate_requirements",
    }


# ------------------------------------------------------------------
# Node: provision_controls
# ------------------------------------------------------------------


async def provision_controls(
    state: SecurityOnboardingEngineState,
) -> dict[str, Any]:
    """Provision security controls for generated
    requirements."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    controls = await toolkit.provision_controls(
        requirements=state.requirements,
        service_name=state.service_name,
        environment=state.environment,
    )

    step = _step(
        state.reasoning_chain,
        "provision_controls",
        f"Provisioning for {len(state.requirements)} requirements",
        f"Provisioned {len(controls)} controls",
        start,
        "control_provisioner",
    )

    return {
        "controls": controls,
        "controls_provisioned": len(controls),
        "stage": SOEStage.PROVISION_CONTROLS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "provision_controls",
    }


# ------------------------------------------------------------------
# Node: validate_onboarding
# ------------------------------------------------------------------


async def validate_onboarding(
    state: SecurityOnboardingEngineState,
) -> dict[str, Any]:
    """Validate provisioned controls against requirements."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    validation = await toolkit.validate_onboarding(
        controls=state.controls,
        requirements=state.requirements,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "controls": state.controls[:10],
                "requirements": state.requirements[:10],
                "total_controls": len(state.controls),
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_VALIDATE,
            user_prompt=f"Validate controls:\n{ctx}",
            schema=ValidationOutput,
        )
        if isinstance(llm_out, ValidationOutput):
            validation.update(
                {
                    "passed": llm_out.passed,
                    "failed": llm_out.failed,
                    "compliance_met": llm_out.compliance_met,
                    "gaps": llm_out.gaps,
                    "remediation_needed": llm_out.remediation_needed,
                }
            )
        logger.info(
            "llm_enhanced",
            node="validate_onboarding",
            passed=llm_out.passed,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="validate_onboarding",
        )

    passed = validation.get("passed", 0)
    failed = validation.get("failed", 0)
    compliance_met = validation.get("compliance_met", False)

    step = _step(
        state.reasoning_chain,
        "validate_onboarding",
        f"Validating {len(state.controls)} controls",
        f"{passed} passed, {failed} failed",
        start,
        "validator",
    )

    return {
        "validation": validation,
        "controls_passed": passed,
        "controls_failed": failed,
        "onboarding_complete": compliance_met and failed == 0,
        "stage": SOEStage.VALIDATE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "validate_onboarding",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: SecurityOnboardingEngineState,
) -> dict[str, Any]:
    """Generate the final onboarding report with readiness
    assessment and recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    total = state.controls_provisioned if state.controls_provisioned > 0 else 1
    readiness = (state.controls_passed / total) * 100

    report: dict[str, Any] = {
        "service_name": state.service_name,
        "total_requirements": state.total_requirements,
        "controls_provisioned": state.controls_provisioned,
        "controls_passed": state.controls_passed,
        "controls_failed": state.controls_failed,
        "readiness_score": readiness,
        "onboarding_complete": state.onboarding_complete,
    }

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "service_name": state.service_name,
                "tier": state.tier.value,
                "risk_profile": state.risk_profile,
                "total_requirements": state.total_requirements,
                "controls_passed": state.controls_passed,
                "controls_failed": state.controls_failed,
                "validation": state.validation,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate onboarding report:\n{ctx}",
            schema=OnboardingReportOutput,
        )
        if isinstance(llm_out, OnboardingReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "readiness_score": llm_out.readiness_score,
                    "recommendations": llm_out.recommendations,
                    "next_review_date": llm_out.next_review_date,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                recommendations=len(llm_out.recommendations),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    # Record metrics
    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    await toolkit.record_metric(
        run_id=state.request_id,
        outcome={
            "service_name": state.service_name,
            "total_requirements": state.total_requirements,
            "controls_passed": state.controls_passed,
            "readiness_score": readiness,
            "duration_ms": duration_ms,
        },
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.service_name}",
        f"Report generated, readiness={readiness:.1f}%",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": SOEStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
