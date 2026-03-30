"""Cloud Storage Scanner Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    CSSStage,
    EncryptionAssessment,
    PermissionFinding,
    ReasoningStep,
    StorageBucket,
    StorageSeverity,
)
from .tools import CloudStorageScannerToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Discover Buckets
# ------------------------------------------------------------------


async def discover_buckets(
    state: dict[str, Any],
    toolkit: CloudStorageScannerToolkit,
) -> dict[str, Any]:
    """Discover storage buckets across providers."""
    logger.info("css.node.discover_buckets")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    providers = state.get("target_providers", [])
    buckets = await toolkit.discover_buckets(
        tenant_id,
        providers or None,
    )
    data = [b.model_dump() for b in buckets]

    public = sum(1 for b in buckets if b.public_access)
    note = f"Discovered {len(buckets)} buckets, {public} with public access"

    return {
        "stage": CSSStage.SCAN_PERMISSIONS.value,
        "buckets": data,
        "total_buckets": len(buckets),
        "current_step": "discover_buckets",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="discover_buckets",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Scan Permissions
# ------------------------------------------------------------------


async def scan_permissions(
    state: dict[str, Any],
    toolkit: CloudStorageScannerToolkit,
) -> dict[str, Any]:
    """Scan bucket permissions and ACLs."""
    logger.info("css.node.scan_permissions")
    state = _to_dict(state)

    buckets = [StorageBucket(**b) for b in state.get("buckets", [])]
    findings = await toolkit.scan_permissions(buckets)
    data = [f.model_dump() for f in findings]

    critical = sum(1 for f in findings if f.severity == StorageSeverity.CRITICAL)
    note = f"Found {len(findings)} permission issues, {critical} critical"

    try:
        from .prompts import (
            SYSTEM_PERMISSIONS,
            PermissionInsight,
        )

        ctx = json.dumps(
            {
                "findings": [
                    {
                        "bucket": f.bucket_name,
                        "severity": f.severity.value,
                        "type": f.finding_type,
                        "public": f.is_public,
                    }
                    for f in findings[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            PermissionInsight,
            await llm_structured(
                system_prompt=SYSTEM_PERMISSIONS,
                user_prompt=(f"Permission scan results:\n{ctx}"),
                schema=PermissionInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="css",
            node="scan_permissions",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="css",
            node="scan_permissions",
        )

    return {
        "stage": (CSSStage.DETECT_SENSITIVE_DATA.value),
        "permission_findings": data,
        "current_step": "scan_permissions",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="scan_permissions",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Detect Sensitive Data
# ------------------------------------------------------------------


async def detect_sensitive_data(
    state: dict[str, Any],
    toolkit: CloudStorageScannerToolkit,
) -> dict[str, Any]:
    """Detect sensitive data in storage buckets."""
    logger.info("css.node.detect_sensitive_data")
    state = _to_dict(state)

    buckets = [StorageBucket(**b) for b in state.get("buckets", [])]
    findings = await toolkit.detect_sensitive_data(
        buckets,
    )
    data = [f.model_dump() for f in findings]

    critical = sum(1 for f in findings if f.severity == StorageSeverity.CRITICAL)
    note = f"Detected {len(findings)} sensitive data exposures, {critical} critical"

    try:
        from .prompts import (
            SYSTEM_SENSITIVE_DATA,
            SensitiveDataInsight,
        )

        ctx = json.dumps(
            {
                "findings": [
                    {
                        "bucket": f.bucket_name,
                        "severity": f.severity.value,
                        "data_type": f.data_type,
                        "count": f.sample_count,
                    }
                    for f in findings[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            SensitiveDataInsight,
            await llm_structured(
                system_prompt=SYSTEM_SENSITIVE_DATA,
                user_prompt=(f"Sensitive data scan:\n{ctx}"),
                schema=SensitiveDataInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="css",
            node="detect_sensitive_data",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="css",
            node="detect_sensitive_data",
        )

    return {
        "stage": CSSStage.ASSESS_ENCRYPTION.value,
        "sensitive_data_findings": data,
        "current_step": "detect_sensitive_data",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="detect_sensitive_data",
                detail=note,
                confidence=0.8,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Assess Encryption
# ------------------------------------------------------------------


async def assess_encryption(
    state: dict[str, Any],
    toolkit: CloudStorageScannerToolkit,
) -> dict[str, Any]:
    """Assess encryption posture for all buckets."""
    logger.info("css.node.assess_encryption")
    state = _to_dict(state)

    buckets = [StorageBucket(**b) for b in state.get("buckets", [])]
    assessments = await toolkit.assess_encryption(
        buckets,
    )
    data = [a.model_dump() for a in assessments]

    unencrypted = sum(1 for a in assessments if not a.encryption_enabled)
    note = f"Assessed {len(assessments)} buckets, {unencrypted} unencrypted"

    try:
        from .prompts import (
            SYSTEM_ENCRYPTION,
            EncryptionInsight,
        )

        ctx = json.dumps(
            {
                "assessments": [
                    {
                        "bucket": a.bucket_name,
                        "encrypted": (a.encryption_enabled),
                        "type": a.encryption_type,
                        "tls": a.in_transit_enforced,
                    }
                    for a in assessments[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            EncryptionInsight,
            await llm_structured(
                system_prompt=SYSTEM_ENCRYPTION,
                user_prompt=(f"Encryption assessment:\n{ctx}"),
                schema=EncryptionInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="css",
            node="assess_encryption",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="css",
            node="assess_encryption",
        )

    return {
        "stage": CSSStage.REMEDIATE_ISSUES.value,
        "encryption_assessments": data,
        "current_step": "assess_encryption",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="assess_encryption",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Remediate Issues
# ------------------------------------------------------------------


async def remediate_issues(
    state: dict[str, Any],
    toolkit: CloudStorageScannerToolkit,
) -> dict[str, Any]:
    """Remediate discovered security issues."""
    logger.info("css.node.remediate_issues")
    state = _to_dict(state)

    perm_findings = [
        PermissionFinding(**f)
        for f in state.get(
            "permission_findings",
            [],
        )
    ]
    enc_assessments = [
        EncryptionAssessment(**a)
        for a in state.get(
            "encryption_assessments",
            [],
        )
    ]
    actions = await toolkit.remediate_issues(
        perm_findings,
        enc_assessments,
    )
    data = [a.model_dump() for a in actions]

    applied = sum(1 for a in actions if a.status == "applied")
    total_findings = (
        len(state.get("permission_findings", []))
        + len(state.get("sensitive_data_findings", []))
        + sum(
            1
            for a in enc_assessments
            if a.severity
            in (
                StorageSeverity.CRITICAL,
                StorageSeverity.HIGH,
                StorageSeverity.MEDIUM,
            )
        )
    )
    critical = sum(1 for f in perm_findings if f.severity == StorageSeverity.CRITICAL) + sum(
        1 for a in enc_assessments if a.severity == StorageSeverity.CRITICAL
    )

    note = f"Remediated {applied}/{len(actions)} issues automatically"

    return {
        "stage": CSSStage.REPORT.value,
        "remediation_actions": data,
        "total_findings": total_findings,
        "critical_findings": critical,
        "current_step": "remediate_issues",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="remediate_issues",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: CloudStorageScannerToolkit,
) -> dict[str, Any]:
    """Compile the final storage security report."""
    logger.info("css.node.report")
    state = _to_dict(state)

    total_buckets = state.get("total_buckets", 0)
    total_findings = state.get("total_findings", 0)
    critical = state.get("critical_findings", 0)
    perm_count = len(state.get("permission_findings", []))
    data_count = len(state.get("sensitive_data_findings", []))
    enc_count = len(state.get("encryption_assessments", []))
    rem_count = len(state.get("remediation_actions", []))

    lines = [
        "# Cloud Storage Security Report",
        "",
        f"**Buckets scanned:** {total_buckets}",
        f"**Total findings:** {total_findings}",
        f"**Critical findings:** {critical}",
        f"**Permission issues:** {perm_count}",
        f"**Sensitive data exposures:** {data_count}",
        f"**Encryption assessments:** {enc_count}",
        f"**Remediation actions:** {rem_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import (
            SYSTEM_REPORT,
            ReportInsight,
        )

        ctx = json.dumps(
            {
                "total_buckets": total_buckets,
                "total_findings": total_findings,
                "critical": critical,
                "perm_issues": perm_count,
                "data_exposures": data_count,
                "enc_issues": enc_count,
                "remediations": rem_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=(f"Storage security report:\n{ctx}"),
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="css",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="css",
            node="report",
        )

    return {
        "stage": CSSStage.REPORT.value,
        "report": report_text,
        "current_step": "report",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="report",
                detail="Final report compiled",
                confidence=0.95,
            ).model_dump()
        ],
    }
