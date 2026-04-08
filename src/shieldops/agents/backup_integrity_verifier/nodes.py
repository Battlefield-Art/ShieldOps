"""Node implementations for the Backup Integrity Verifier
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.backup_integrity_verifier.models import (
    BackupIntegrityVerifierState,
    BIVStage,
    ReasoningStep,
)
from shieldops.agents.backup_integrity_verifier.prompts import (
    SYSTEM_DISCOVER,
    SYSTEM_INTEGRITY,
    SYSTEM_REPORT,
    SYSTEM_RESTORE,
    BackupDiscoveryOutput,
    IntegrityAnalysisOutput,
    RestoreTestOutput,
    VerificationReportOutput,
)
from shieldops.agents.backup_integrity_verifier.tools import (
    BackupIntegrityVerifierToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: BackupIntegrityVerifierToolkit | None = None


def _get_toolkit() -> BackupIntegrityVerifierToolkit:
    if _toolkit is None:
        return BackupIntegrityVerifierToolkit()
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
# Node: discover_backups
# ------------------------------------------------------------------


async def discover_backups(
    state: BackupIntegrityVerifierState,
) -> dict[str, Any]:
    """Discover backup records across target systems
    and storage locations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.discover_backups(
        target_systems=state.target_systems,
        storage_locations=state.storage_locations,
        scope=state.scope,
    )

    backups: list[dict[str, Any]] = list(results)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "target_systems": state.target_systems,
                "storage_locations": state.storage_locations,
                "scope": state.scope,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_DISCOVER,
            user_prompt=f"Discover backups:\n{ctx}",
            schema=BackupDiscoveryOutput,
        )
        if llm_out.backups:  # type: ignore[union-attr]
            backups = [
                *backups,
                *llm_out.backups,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="discover_backups",
            count=len(llm_out.backups),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="discover_backups",
        )

    step = _step(
        state.reasoning_chain,
        "discover_backups",
        (f"Systems: {len(state.target_systems)}, locations={len(state.storage_locations)}"),
        f"Discovered {len(backups)} backups",
        start,
        "backup_manager",
    )

    return {
        "backups": backups,
        "total_backups": len(backups),
        "stage": BIVStage.DISCOVER_BACKUPS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "discover_backups",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: verify_integrity
# ------------------------------------------------------------------


async def verify_integrity(
    state: BackupIntegrityVerifierState,
) -> dict[str, Any]:
    """Verify cryptographic integrity of discovered
    backups."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    checks = await toolkit.verify_integrity(
        backups=state.backups,
    )

    passed = sum(1 for c in checks if c.get("status") == "passed")
    failed = sum(1 for c in checks if c.get("status") == "failed")

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "total_backups": state.total_backups,
                "checks_sample": checks[:5],
                "passed": passed,
                "failed": failed,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_INTEGRITY,
            user_prompt=f"Analyze integrity:\n{ctx}",
            schema=IntegrityAnalysisOutput,
        )
        if llm_out.summary:  # type: ignore[union-attr]
            checks.append(
                {
                    "check_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "risk_assessment": llm_out.risk_assessment,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="verify_integrity",
            risk=llm_out.risk_assessment,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="verify_integrity",
        )

    step = _step(
        state.reasoning_chain,
        "verify_integrity",
        f"Verifying {len(state.backups)} backups",
        f"{passed} passed, {failed} failed",
        start,
        "integrity_checker",
    )

    return {
        "integrity_checks": checks,
        "passed_integrity": passed,
        "failed_integrity": failed,
        "stage": BIVStage.VERIFY_INTEGRITY,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "verify_integrity",
    }


# ------------------------------------------------------------------
# Node: check_encryption
# ------------------------------------------------------------------


async def check_encryption(
    state: BackupIntegrityVerifierState,
) -> dict[str, Any]:
    """Validate encryption compliance of backup data."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    checks = await toolkit.check_encryption(
        backups=state.backups,
    )

    compliant = sum(1 for c in checks if c.get("encrypted") and c.get("key_rotation_compliant"))

    step = _step(
        state.reasoning_chain,
        "check_encryption",
        f"Checking encryption on {len(state.backups)} backups",
        f"{compliant} compliant of {len(checks)} checked",
        start,
        "encryption_validator",
    )

    return {
        "encryption_checks": checks,
        "encryption_compliant": compliant,
        "stage": BIVStage.CHECK_ENCRYPTION,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "check_encryption",
    }


# ------------------------------------------------------------------
# Node: test_restore
# ------------------------------------------------------------------


async def test_restore(
    state: BackupIntegrityVerifierState,
) -> dict[str, Any]:
    """Execute restore tests against selected backups."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    tests = await toolkit.test_restore(
        backups=state.backups,
    )

    success_count = sum(1 for t in tests if t.get("success"))
    rate = success_count / len(tests) if tests else 0.0

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "test_count": len(tests),
                "success_count": success_count,
                "tests_sample": tests[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_RESTORE,
            user_prompt=f"Analyze restore tests:\n{ctx}",
            schema=RestoreTestOutput,
        )
        if llm_out.issues:  # type: ignore[union-attr]
            tests.append(
                {
                    "test_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "success_rate": llm_out.success_rate,  # type: ignore[union-attr]
                    "issues": llm_out.issues,  # type: ignore[union-attr]
                    "recommendations": llm_out.recommendations,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="test_restore",
            issues=len(llm_out.issues),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="test_restore",
        )

    step = _step(
        state.reasoning_chain,
        "test_restore",
        f"Testing restore of {len(state.backups)} backups",
        f"{success_count} succeeded, rate={rate:.1%}",
        start,
        "restore_tester",
    )

    return {
        "restore_tests": tests,
        "restore_success_rate": rate,
        "stage": BIVStage.TEST_RESTORE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "test_restore",
    }


# ------------------------------------------------------------------
# Node: assess_coverage
# ------------------------------------------------------------------


async def assess_coverage(
    state: BackupIntegrityVerifierState,
) -> dict[str, Any]:
    """Assess backup coverage across target systems."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    coverage = await toolkit.assess_coverage(
        backups=state.backups,
        target_systems=state.target_systems,
    )

    coverage_pct = coverage.get("coverage_pct", 0.0)

    step = _step(
        state.reasoning_chain,
        "assess_coverage",
        (f"Assessing coverage for {len(state.target_systems)} systems"),
        f"Coverage: {coverage_pct:.1%}",
        start,
        "coverage_assessor",
    )

    return {
        "coverage": coverage,
        "coverage_pct": coverage_pct,
        "stage": BIVStage.ASSESS_COVERAGE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_coverage",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: BackupIntegrityVerifierState,
) -> dict[str, Any]:
    """Generate the final backup verification report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {}

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "total_backups": state.total_backups,
                "passed_integrity": state.passed_integrity,
                "failed_integrity": state.failed_integrity,
                "encryption_compliant": state.encryption_compliant,
                "restore_success_rate": state.restore_success_rate,
                "coverage_pct": state.coverage_pct,
                "coverage": state.coverage,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate verification report:\n{ctx}",
            schema=VerificationReportOutput,
        )
        if isinstance(llm_out, VerificationReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "overall_health": llm_out.overall_health,
                    "recommendations": llm_out.recommendations,
                    "compliance_status": llm_out.compliance_status,
                    "risk_rating": llm_out.risk_rating,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                health=llm_out.overall_health,
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    # Track metric
    await toolkit.record_metric(
        metric_name="backup_verification_completed",
        value=float(state.total_backups),
        tags={
            "passed": str(state.passed_integrity),
            "failed": str(state.failed_integrity),
        },
    )

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.total_backups} backups",
        (f"Report generated, health={report.get('overall_health', 'unknown')}"),
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": BIVStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
