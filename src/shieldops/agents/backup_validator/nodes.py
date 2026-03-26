"""Backup Validator Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog

from shieldops.utils.llm import llm_structured

from .models import (
    BackupGap,
    BackupRecord,
    BackupStage,
    IntegrityCheck,
    ValidationStatus,
)
from .prompts import (
    SYSTEM_GAP_ANALYSIS,
    SYSTEM_RECOVERY_ANALYSIS,
    SYSTEM_REPORT,
    BackupReportResult,
    GapAnalysisResult,
    RecoveryAnalysisResult,
)
from .tools import BackupValidatorToolkit

logger = structlog.get_logger()


async def inventory_backups(
    state: dict[str, Any], toolkit: BackupValidatorToolkit
) -> dict[str, Any]:
    """Discover and inventory all backups."""
    logger.info("backup_validator.node.inventory")

    tenant_id = state.get("tenant_id", "")
    backups = await toolkit.inventory_backups(tenant_id)
    backups_data = [b.model_dump(mode="json") for b in backups]

    return {
        "stage": BackupStage.VALIDATE_INTEGRITY.value,
        "backups": backups_data,
        "total_backups": len(backups),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Inventoried {len(backups)} backups"],
    }


async def validate_integrity(
    state: dict[str, Any], toolkit: BackupValidatorToolkit
) -> dict[str, Any]:
    """Validate backup integrity."""
    logger.info("backup_validator.node.validate_integrity")

    raw_backups = state.get("backups", [])
    backups = [BackupRecord(**b) for b in raw_backups]
    checks = await toolkit.validate_integrity(backups)
    checks_data = [c.model_dump() for c in checks]

    valid_count = sum(
        1 for c in checks if c.status == ValidationStatus.VALID
    )
    return {
        "stage": BackupStage.TEST_RECOVERY.value,
        "integrity_checks": checks_data,
        "valid_count": valid_count,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Validated {len(checks)} backups, {valid_count} valid"],
    }


async def test_recovery(
    state: dict[str, Any], toolkit: BackupValidatorToolkit
) -> dict[str, Any]:
    """Test backup recovery."""
    logger.info("backup_validator.node.test_recovery")

    raw_backups = state.get("backups", [])
    backups = [BackupRecord(**b) for b in raw_backups]
    tests = await toolkit.test_recovery(backups)
    tests_data = [t.model_dump() for t in tests]

    success_count = sum(1 for t in tests if t.success)
    rate = (success_count / len(tests) * 100) if tests else 0.0

    reasoning_note = (
        f"Tested {len(tests)} recoveries, {success_count} successful "
        f"({rate:.0f}%)"
    )

    if tests:
        try:
            context = json.dumps(
                {
                    "tests": [
                        {
                            "backup_id": t.backup_id,
                            "recovery_time_min": t.recovery_time_min,
                            "success": t.success,
                            "rto_met": t.rto_met,
                        }
                        for t in tests
                    ],
                },
                default=str,
            )
            result = cast(
                RecoveryAnalysisResult,
                await llm_structured(
                    system_prompt=SYSTEM_RECOVERY_ANALYSIS,
                    user_prompt=f"Recovery test context:\n{context}",
                    schema=RecoveryAnalysisResult,
                ),
            )
            reasoning_note = f"{result.summary}. {reasoning_note}"
        except Exception:
            logger.debug("llm_fallback", agent="backup_validator", node="recovery")

    return {
        "stage": BackupStage.ASSESS_GAPS.value,
        "recovery_tests": tests_data,
        "recovery_success_rate": round(rate, 1),
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def assess_gaps(
    state: dict[str, Any], toolkit: BackupValidatorToolkit
) -> dict[str, Any]:
    """Assess backup coverage gaps."""
    logger.info("backup_validator.node.assess_gaps")

    raw_backups = state.get("backups", [])
    raw_checks = state.get("integrity_checks", [])
    backups = [BackupRecord(**b) for b in raw_backups]
    checks = [IntegrityCheck(**c) for c in raw_checks]

    gaps = await toolkit.assess_gaps(backups, checks)
    gaps_data = [g.model_dump() for g in gaps]

    reasoning_note = f"Identified {len(gaps)} backup gaps"

    if gaps:
        try:
            context = json.dumps(
                {
                    "gaps": [
                        {
                            "service": g.service,
                            "gap_type": g.gap_type,
                            "severity": g.severity,
                        }
                        for g in gaps
                    ],
                },
                default=str,
            )
            result = cast(
                GapAnalysisResult,
                await llm_structured(
                    system_prompt=SYSTEM_GAP_ANALYSIS,
                    user_prompt=f"Gap analysis context:\n{context}",
                    schema=GapAnalysisResult,
                ),
            )
            reasoning_note = f"{result.summary}. {reasoning_note}"
        except Exception:
            logger.debug("llm_fallback", agent="backup_validator", node="assess_gaps")

    return {
        "stage": BackupStage.REMEDIATE.value,
        "gaps": gaps_data,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def remediate(
    state: dict[str, Any], toolkit: BackupValidatorToolkit
) -> dict[str, Any]:
    """Remediate identified backup gaps."""
    logger.info("backup_validator.node.remediate")

    raw_gaps = state.get("gaps", [])
    remediations: list[dict[str, Any]] = []

    for raw in raw_gaps:
        if raw.get("severity") in ("critical", "high"):
            gap = BackupGap(**raw)
            result = await toolkit.remediate_gap(gap)
            remediations.append(result)

    return {
        "stage": BackupStage.REPORT.value,
        "remediations": remediations,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Scheduled {len(remediations)} remediations"],
    }


async def generate_report(
    state: dict[str, Any], toolkit: BackupValidatorToolkit
) -> dict[str, Any]:
    """Generate backup validation report."""
    logger.info("backup_validator.node.report")

    total = state.get("total_backups", 0)
    valid = state.get("valid_count", 0)
    rate = state.get("recovery_success_rate", 0.0)
    gaps = state.get("gaps", [])
    summary = (
        f"Validated {total} backups: {valid} valid, "
        f"{rate}% recovery success, {len(gaps)} gaps found"
    )

    try:
        context = json.dumps(
            {
                "total_backups": total,
                "valid_count": valid,
                "recovery_success_rate": rate,
                "gaps_count": len(gaps),
                "remediations": state.get("remediations", []),
            },
            default=str,
        )
        result = cast(
            BackupReportResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Backup report context:\n{context}",
                schema=BackupReportResult,
            ),
        )
        summary = result.executive_summary
    except Exception:
        logger.debug("llm_fallback", agent="backup_validator", node="report")

    return {
        "stage": BackupStage.REPORT.value,
        "summary": summary,
        "reasoning_chain": state.get("reasoning_chain", []) + [summary],
    }
