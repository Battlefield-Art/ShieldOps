"""Node implementations for Remediation Verifier Agent."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.remediation_verifier.models import (
    ReasoningStep,
    RemediationVerifierState,
    TestType,
    VerificationResult,
    VerifierStage,
)
from shieldops.agents.remediation_verifier.prompts import (
    SYSTEM_ASSESS,
    SYSTEM_DESIGN_TEST,
    SYSTEM_REPORT,
    AssessmentResult,
    TestDesignResult,
    VerifierReportResult,
)
from shieldops.agents.remediation_verifier.tools import (
    RemediationVerifierToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: RemediationVerifierToolkit | None = None


def _get_toolkit() -> RemediationVerifierToolkit:
    if _toolkit is None:
        return RemediationVerifierToolkit()
    return _toolkit


async def collect_remediations(
    state: RemediationVerifierState,
) -> dict[str, Any]:
    """Collect recent remediations to verify."""
    start = datetime.now(UTC)
    tk = _get_toolkit()

    records = await tk.collect_remediations()

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="collect_remediations",
        input_summary="all recent remediations",
        output_summary=(f"Collected {len(records)} remediations"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="remediation_db",
    )
    return {
        "remediations_collected": records,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": (VerifierStage.COLLECT_REMEDIATIONS),
    }


async def design_verification_tests(
    state: RemediationVerifierState,
) -> dict[str, Any]:
    """Design verification tests for each remediation."""
    start = datetime.now(UTC)
    tk = _get_toolkit()
    tests = []

    type_map = {
        "patch": TestType.RESCAN,
        "config_change": TestType.CONFIG_CHECK,
        "disable": TestType.ACCESS_CHECK,
        "waf_rule": TestType.EXPLOIT_RETEST,
    }

    for rem in state.remediations_collected:
        test_type = type_map.get(rem.remediation_type, TestType.RESCAN)

        # LLM-enhanced test design
        ctx = (
            f"Finding: {rem.finding_title}\n"
            f"Fix: {rem.remediation_type}\n"
            f"Asset: {rem.asset}\n"
            f"Severity: {rem.original_severity}"
        )
        try:
            result = cast(
                TestDesignResult,
                await llm_structured(
                    system_prompt=SYSTEM_DESIGN_TEST,
                    user_prompt=ctx,
                    schema=TestDesignResult,
                ),
            )
            desc = result.description
        except Exception as e:
            logger.error(
                "llm_test_design_failed",
                error=str(e),
            )
            desc = f"Verify {rem.remediation_type} on {rem.asset}"

        test = await tk.design_test(rem, test_type)
        test.description = desc
        tests.append(test)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="design_verification_tests",
        input_summary=(f"{len(state.remediations_collected)} remediations"),
        output_summary=(f"Designed {len(tests)} tests"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )
    return {
        "tests_designed": tests,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": (VerifierStage.DESIGN_VERIFICATION_TESTS),
    }


async def execute_tests(
    state: RemediationVerifierState,
) -> dict[str, Any]:
    """Execute all verification tests."""
    start = datetime.now(UTC)
    tk = _get_toolkit()
    executions = []

    for test in state.tests_designed:
        exe = await tk.execute_test(test)
        executions.append(exe)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="execute_tests",
        input_summary=(f"{len(state.tests_designed)} tests"),
        output_summary=(f"Executed {len(executions)} tests"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="test_runner",
    )
    return {
        "tests_executed": executions,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": VerifierStage.EXECUTE_TESTS,
    }


async def assess_results(
    state: RemediationVerifierState,
) -> dict[str, Any]:
    """Assess test results."""
    start = datetime.now(UTC)
    tk = _get_toolkit()
    assessments = []
    fixed = 0
    vulnerable = 0

    for exe in state.tests_executed:
        assessment = await tk.assess_result(exe)

        # LLM-enhanced assessment
        ctx = (
            f"Test result: {exe.result}\n"
            f"Actual: {exe.actual_output}\n"
            f"Expected: {exe.expected_output}"
        )
        try:
            result = cast(
                AssessmentResult,
                await llm_structured(
                    system_prompt=SYSTEM_ASSESS,
                    user_prompt=ctx,
                    schema=AssessmentResult,
                ),
            )
            assessment.confidence = result.confidence
            assessment.details = result.details
            assessment.needs_attention = result.needs_attention
        except Exception as e:
            logger.error("llm_assess_failed", error=str(e))

        assessments.append(assessment)

        if assessment.overall_result == (VerificationResult.FIXED):
            fixed += 1
        else:
            vulnerable += 1

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="assess_results",
        input_summary=(f"{len(state.tests_executed)} tests"),
        output_summary=(f"fixed={fixed}, vulnerable={vulnerable}"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )
    return {
        "results_assessed": assessments,
        "verified_fixed_count": fixed,
        "still_vulnerable_count": vulnerable,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": VerifierStage.ASSESS_RESULTS,
    }


async def flag_regressions(
    state: RemediationVerifierState,
) -> dict[str, Any]:
    """Flag regressions and new issues."""
    start = datetime.now(UTC)
    tk = _get_toolkit()
    flags = []

    regression_results = {
        VerificationResult.REGRESSION,
        VerificationResult.NEW_ISSUE,
        VerificationResult.NOT_FIXED,
    }

    for exe in state.tests_executed:
        if exe.result in regression_results:
            flag = await tk.flag_regression(
                exe,
                f"Regression: {exe.result} — {exe.actual_output}",
            )
            flags.append(flag)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="flag_regressions",
        input_summary=(f"{len(state.tests_executed)} test results"),
        output_summary=(f"Flagged {len(flags)} regressions"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="alert_system",
    )
    return {
        "regressions_found": flags,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": (VerifierStage.FLAG_REGRESSIONS),
    }


async def generate_report(
    state: RemediationVerifierState,
) -> dict[str, Any]:
    """Generate verification report."""
    start = datetime.now(UTC)

    ctx = (
        f"Verified: "
        f"{len(state.remediations_collected)}\n"
        f"Fixed: {state.verified_fixed_count}\n"
        f"Vulnerable: {state.still_vulnerable_count}\n"
        f"Regressions: {len(state.regressions_found)}"
    )

    report = (
        f"Verification: "
        f"{state.verified_fixed_count} fixed, "
        f"{state.still_vulnerable_count} still "
        f"vulnerable, "
        f"{len(state.regressions_found)} regressions."
    )

    try:
        result = cast(
            VerifierReportResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=ctx,
                schema=VerifierReportResult,
            ),
        )
        report = f"{result.title}\n\n{result.executive_summary}\nRisk: {result.risk_assessment}"
    except Exception as e:
        logger.error("llm_report_failed", error=str(e))

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary=ctx[:100],
        output_summary=report[:200],
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )

    total = sum(s.duration_ms for s in [*state.reasoning_chain, step])
    return {
        "report_summary": report,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": VerifierStage.REPORT,
        "duration_ms": total,
    }
