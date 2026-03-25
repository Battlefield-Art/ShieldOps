"""Secrets Scanner Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import ScannerStage
from .tools import SecretsScannerToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def scan_sources(
    state: dict[str, Any],
    toolkit: SecretsScannerToolkit,
) -> dict[str, Any]:
    """Scan configured targets for potential secret patterns."""
    logger.info("secrets_scanner.node.scan_sources")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    targets = state.get("scan_targets", [])
    session_start = time.time()

    findings = await toolkit.scan_sources(tenant_id=tenant_id, targets=targets)
    finding_dicts = [f.model_dump() for f in findings]

    return {
        "secret_findings": finding_dicts,
        "stage": ScannerStage.SCAN_SOURCES.value,
        "session_start": session_start,
        "current_step": "scan_sources",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Scanned {len(targets)} targets, found {len(findings)} potential secrets"],
    }


async def detect_secrets(
    state: dict[str, Any],
    toolkit: SecretsScannerToolkit,
) -> dict[str, Any]:
    """Refine detections using LLM analysis to filter false positives."""
    logger.info("secrets_scanner.node.detect_secrets")
    state = _to_dict(state)
    findings = state.get("secret_findings", [])

    reasoning_note = f"Analyzing {len(findings)} raw findings for false positives"

    # LLM enhancement: classify true vs false positives
    try:
        from .prompts import SYSTEM_SCAN_ANALYSIS, SecretAnalysisOutput

        context = json.dumps(
            {
                "finding_count": len(findings),
                "findings_sample": findings[:20],
                "secret_types": list({f.get("secret_type", "") for f in findings}),
            },
            default=str,
        )
        llm_result = cast(
            SecretAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_SCAN_ANALYSIS,
                user_prompt=f"Secret scan results:\n{context}",
                schema=SecretAnalysisOutput,
            ),
        )
        logger.info("llm_enhanced", agent="secrets_scanner", node="detect_secrets")

        # Filter out LLM-identified false positives
        fp_ids = set(llm_result.false_positive_ids)
        if fp_ids:
            findings = [f for f in findings if f.get("id", "") not in fp_ids]
            reasoning_note = (
                f"{llm_result.summary} — removed {len(fp_ids)} false positives, "
                f"{len(findings)} findings remain"
            )
        else:
            reasoning_note = f"{llm_result.summary} — all {len(findings)} findings confirmed"
    except Exception:
        logger.debug("llm_fallback", agent="secrets_scanner", node="detect_secrets")

    return {
        "secret_findings": findings,
        "stage": ScannerStage.DETECT_SECRETS.value,
        "current_step": "detect_secrets",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def classify_severity(
    state: dict[str, Any],
    toolkit: SecretsScannerToolkit,
) -> dict[str, Any]:
    """Classify severity of each finding."""
    logger.info("secrets_scanner.node.classify_severity")
    state = _to_dict(state)
    raw_findings = state.get("secret_findings", [])

    from .models import SecretFinding

    findings = [SecretFinding(**f) if isinstance(f, dict) else f for f in raw_findings]
    assessments = await toolkit.classify_severity(findings)
    assessment_dicts = [a.model_dump() for a in assessments]

    reasoning_note = (
        f"Classified severity for {len(assessments)} findings: "
        f"{sum(1 for a in assessments if a.severity == 'critical')} critical, "
        f"{sum(1 for a in assessments if a.severity == 'high')} high"
    )

    # LLM enhancement: deeper risk analysis
    try:
        from .prompts import SYSTEM_SEVERITY_ASSESSMENT, SeverityOutput

        context = json.dumps(
            {
                "findings": [f.model_dump() for f in findings[:20]],
                "assessments": assessment_dicts[:20],
            },
            default=str,
        )
        llm_result = cast(
            SeverityOutput,
            await llm_structured(
                system_prompt=SYSTEM_SEVERITY_ASSESSMENT,
                user_prompt=f"Severity assessment data:\n{context}",
                schema=SeverityOutput,
            ),
        )
        logger.info("llm_enhanced", agent="secrets_scanner", node="classify_severity")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="secrets_scanner", node="classify_severity")

    return {
        "severity_assessments": assessment_dicts,
        "stage": ScannerStage.CLASSIFY_SEVERITY.value,
        "current_step": "classify_severity",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def verify_exposure(
    state: dict[str, Any],
    toolkit: SecretsScannerToolkit,
) -> dict[str, Any]:
    """Verify exposure level and active status for each finding."""
    logger.info("secrets_scanner.node.verify_exposure")
    state = _to_dict(state)
    raw_findings = state.get("secret_findings", [])

    from .models import SecretFinding

    findings = [SecretFinding(**f) if isinstance(f, dict) else f for f in raw_findings]
    verified = await toolkit.verify_exposure(findings)
    verified_dicts = [f.model_dump() for f in verified]

    active_count = sum(1 for f in verified if f.is_active)
    public_count = sum(1 for f in verified if f.exposure_level == "public")
    reasoning_note = (
        f"Verified {len(verified)} findings: {active_count} active, {public_count} publicly exposed"
    )

    # LLM enhancement: exposure intelligence
    try:
        from .prompts import SYSTEM_EXPOSURE_VERIFICATION, ExposureOutput

        context = json.dumps(
            {"verified_findings": verified_dicts[:20]},
            default=str,
        )
        llm_result = cast(
            ExposureOutput,
            await llm_structured(
                system_prompt=SYSTEM_EXPOSURE_VERIFICATION,
                user_prompt=f"Exposure verification data:\n{context}",
                schema=ExposureOutput,
            ),
        )
        logger.info("llm_enhanced", agent="secrets_scanner", node="verify_exposure")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="secrets_scanner", node="verify_exposure")

    return {
        "secret_findings": verified_dicts,
        "stage": ScannerStage.VERIFY_EXPOSURE.value,
        "current_step": "verify_exposure",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def remediate(
    state: dict[str, Any],
    toolkit: SecretsScannerToolkit,
) -> dict[str, Any]:
    """Remediate active, exposed secrets — rotate or revoke credentials."""
    logger.info("secrets_scanner.node.remediate")
    state = _to_dict(state)
    raw_findings = state.get("secret_findings", [])
    raw_assessments = state.get("severity_assessments", [])

    from .models import SecretFinding, SeverityAssessment

    findings = [SecretFinding(**f) if isinstance(f, dict) else f for f in raw_findings]
    assessments = [SeverityAssessment(**a) if isinstance(a, dict) else a for a in raw_assessments]

    # Only remediate active findings
    active_findings = [f for f in findings if f.is_active]

    reasoning_note = f"Remediating {len(active_findings)} active secrets"

    # LLM enhancement: remediation planning
    try:
        from .prompts import SYSTEM_REMEDIATION_PLANNING, RemediationOutput

        context = json.dumps(
            {
                "active_findings": [f.model_dump() for f in active_findings[:20]],
                "assessments": [a.model_dump() for a in assessments[:20]],
            },
            default=str,
        )
        llm_result = cast(
            RemediationOutput,
            await llm_structured(
                system_prompt=SYSTEM_REMEDIATION_PLANNING,
                user_prompt=f"Remediation planning data:\n{context}",
                schema=RemediationOutput,
            ),
        )
        logger.info("llm_enhanced", agent="secrets_scanner", node="remediate")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="secrets_scanner", node="remediate")

    actions = await toolkit.remediate_secrets(active_findings, assessments)
    action_dicts = [a.model_dump() for a in actions]

    success_count = sum(1 for a in actions if a.success)
    reasoning_note += f" — {success_count}/{len(actions)} auto-remediated"

    return {
        "remediation_actions": action_dicts,
        "stage": ScannerStage.REMEDIATE.value,
        "current_step": "remediate",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: SecretsScannerToolkit,
) -> dict[str, Any]:
    """Generate final scan report with statistics."""
    logger.info("secrets_scanner.node.generate_report")
    state = _to_dict(state)

    findings = state.get("secret_findings", [])
    assessments = state.get("severity_assessments", [])
    actions = state.get("remediation_actions", [])
    session_start = state.get("session_start", time.time())

    # Compute statistics
    active_count = sum(1 for f in findings if f.get("is_active", False))
    public_count = sum(1 for f in findings if f.get("exposure_level") == "public")
    critical_count = sum(1 for a in assessments if a.get("severity") == "critical")
    high_count = sum(1 for a in assessments if a.get("severity") == "high")
    remediated_count = sum(1 for a in actions if a.get("success", False))

    # Secret type distribution
    type_dist: dict[str, int] = {}
    for f in findings:
        st = f.get("secret_type", "unknown")
        type_dist[st] = type_dist.get(st, 0) + 1

    duration_ms = (time.time() - session_start) * 1000

    stats = {
        "total_findings": len(findings),
        "active_secrets": active_count,
        "publicly_exposed": public_count,
        "critical_severity": critical_count,
        "high_severity": high_count,
        "remediated": remediated_count,
        "secret_type_distribution": type_dist,
        "scan_duration_ms": round(duration_ms, 2),
    }

    return {
        "stats": stats,
        "stage": ScannerStage.REPORT.value,
        "current_step": "generate_report",
        "session_duration_ms": duration_ms,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Report: {len(findings)} findings, {active_count} active, "
            f"{critical_count} critical, {remediated_count} remediated"
        ],
    }
