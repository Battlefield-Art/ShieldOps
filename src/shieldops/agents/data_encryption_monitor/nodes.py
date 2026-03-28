"""Data Encryption Monitor Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    CertificateHealth,
    CertificateStatus,
    EncryptionAsset,
    KeyRotationStatus,
)
from .tools import DataEncryptionMonitorToolkit

logger = structlog.get_logger()

_toolkit: DataEncryptionMonitorToolkit | None = None


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def scan_assets(
    state: dict[str, Any],
    toolkit: DataEncryptionMonitorToolkit,
) -> dict[str, Any]:
    """Scan infrastructure for data stores and services."""
    logger.info("encryption_monitor.node.scan_assets")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    session_start = time.time()

    providers = state.get("cloud_providers", None)
    asset_types = state.get("asset_types", None)

    assets = await toolkit.scan_assets(
        tenant_id=tenant_id,
        cloud_providers=providers,
        asset_types=asset_types,
    )
    asset_dicts = [a.model_dump() for a in assets]

    encrypted = sum(1 for a in assets if a.is_encrypted)
    total = len(assets)
    coverage = (encrypted / total * 100) if total else 0.0

    return {
        "assets_scanned": asset_dicts,
        "encryption_coverage_pct": round(coverage, 1),
        "session_start": session_start,
        "current_step": "scan_assets",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Scanned {total} assets; {encrypted} encrypted ({coverage:.1f}% coverage)"],
    }


async def assess_encryption(
    state: dict[str, Any],
    toolkit: DataEncryptionMonitorToolkit,
) -> dict[str, Any]:
    """Assess encryption posture of discovered assets."""
    logger.info("encryption_monitor.node.assess_encryption")
    state = _to_dict(state)
    asset_dicts = state.get("assets_scanned", [])
    assets = [EncryptionAsset(**a) for a in asset_dicts]

    assessments: list[dict[str, Any]] = []
    for asset in assets:
        assessment = {
            "asset_id": asset.id,
            "name": asset.name,
            "is_encrypted": asset.is_encrypted,
            "encryption_type": asset.encryption_type.value,
            "algorithm": asset.algorithm,
            "strength": _assess_algorithm_strength(asset.algorithm),
            "compliance_tags": asset.compliance_tags,
        }
        assessments.append(assessment)

    # LLM enhancement: encryption assessment
    reasoning_note = f"Assessed {len(assessments)} assets for encryption posture"
    try:
        from .prompts import (
            SYSTEM_ENCRYPTION_ASSESSMENT,
            EncryptionAssessmentResult,
        )

        context = json.dumps(
            {
                "total_assets": len(assets),
                "encrypted": sum(1 for a in assets if a.is_encrypted),
                "assessments": assessments[:20],
            },
            default=str,
        )
        llm_result = cast(
            EncryptionAssessmentResult,
            await llm_structured(
                system_prompt=SYSTEM_ENCRYPTION_ASSESSMENT,
                user_prompt=(f"Encryption assessment:\n{context}"),
                schema=EncryptionAssessmentResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_encryption_monitor",
            node="assess_encryption",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_encryption_monitor",
            node="assess_encryption",
        )

    return {
        "encryption_assessments": assessments,
        "current_step": "assess_encryption",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning_note]),
    }


async def check_key_rotation(
    state: dict[str, Any],
    toolkit: DataEncryptionMonitorToolkit,
) -> dict[str, Any]:
    """Check key rotation schedules."""
    logger.info("encryption_monitor.node.check_key_rotation")
    state = _to_dict(state)
    asset_dicts = state.get("assets_scanned", [])
    assets = [EncryptionAsset(**a) for a in asset_dicts]

    statuses = await toolkit.check_key_rotation(assets=assets)
    status_dicts = [s.model_dump() for s in statuses]

    overdue = sum(1 for s in statuses if s.is_overdue)

    # LLM enhancement: key rotation analysis
    reasoning_note = f"Checked {len(statuses)} keys; {overdue} overdue"
    try:
        from .prompts import (
            SYSTEM_KEY_ROTATION,
            KeyRotationAnalysisResult,
        )

        context = json.dumps(
            {
                "total_keys": len(statuses),
                "overdue": overdue,
                "statuses": status_dicts,
            },
            default=str,
        )
        llm_result = cast(
            KeyRotationAnalysisResult,
            await llm_structured(
                system_prompt=SYSTEM_KEY_ROTATION,
                user_prompt=(f"Key rotation status:\n{context}"),
                schema=KeyRotationAnalysisResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_encryption_monitor",
            node="check_key_rotation",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_encryption_monitor",
            node="check_key_rotation",
        )

    return {
        "key_rotation_statuses": status_dicts,
        "current_step": "check_key_rotation",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning_note]),
    }


async def check_certificates(
    state: dict[str, Any],
    toolkit: DataEncryptionMonitorToolkit,
) -> dict[str, Any]:
    """Check TLS/SSL certificate health."""
    logger.info("encryption_monitor.node.check_certificates")
    state = _to_dict(state)
    asset_dicts = state.get("assets_scanned", [])
    assets = [EncryptionAsset(**a) for a in asset_dicts]

    certs = await toolkit.check_certificates(assets=assets)
    cert_dicts = [c.model_dump() for c in certs]

    expired = sum(1 for c in certs if c.status == CertificateStatus.EXPIRED)
    expiring = sum(1 for c in certs if c.status == CertificateStatus.EXPIRING_SOON)

    return {
        "certificate_health": cert_dicts,
        "current_step": "check_certificates",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Checked {len(certs)} certificates; {expired} expired, {expiring} expiring soon"],
    }


async def identify_gaps(
    state: dict[str, Any],
    toolkit: DataEncryptionMonitorToolkit,
) -> dict[str, Any]:
    """Identify encryption gaps and weaknesses."""
    logger.info("encryption_monitor.node.identify_gaps")
    state = _to_dict(state)

    assets = [EncryptionAsset(**a) for a in state.get("assets_scanned", [])]
    key_statuses = [KeyRotationStatus(**k) for k in state.get("key_rotation_statuses", [])]
    certs = [CertificateHealth(**c) for c in state.get("certificate_health", [])]

    gaps = await toolkit.identify_gaps(
        assets=assets,
        key_statuses=key_statuses,
        certificates=certs,
    )
    gap_dicts = [g.model_dump() for g in gaps]

    critical = sum(1 for g in gaps if g.severity == "critical")
    high = sum(1 for g in gaps if g.severity == "high")

    return {
        "encryption_gaps": gap_dicts,
        "current_step": "identify_gaps",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Found {len(gaps)} gaps; {critical} critical, {high} high severity"],
    }


async def report(
    state: dict[str, Any],
    toolkit: DataEncryptionMonitorToolkit,
) -> dict[str, Any]:
    """Generate final encryption posture report."""
    logger.info("encryption_monitor.node.report")
    state = _to_dict(state)
    session_start = state.get("session_start", time.time())
    duration_ms = (time.time() - session_start) * 1000

    assets = state.get("assets_scanned", [])
    keys = state.get("key_rotation_statuses", [])
    certs = state.get("certificate_health", [])
    gaps = state.get("encryption_gaps", [])

    # Severity breakdown
    severity_counts: dict[str, int] = {}
    for g in gaps:
        sev = g.get("severity", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Gap type breakdown
    gap_type_counts: dict[str, int] = {}
    for g in gaps:
        gt = g.get("gap_type", "unknown")
        gap_type_counts[gt] = gap_type_counts.get(gt, 0) + 1

    encrypted_count = sum(1 for a in assets if a.get("is_encrypted", False))
    total = len(assets)
    coverage = (encrypted_count / total * 100) if total else 0.0

    stats = {
        "assets_scanned": total,
        "assets_encrypted": encrypted_count,
        "encryption_coverage_pct": round(coverage, 1),
        "keys_checked": len(keys),
        "keys_overdue": sum(1 for k in keys if k.get("is_overdue", False)),
        "certificates_checked": len(certs),
        "certificates_expired": sum(1 for c in certs if c.get("status") == "expired"),
        "certificates_expiring": sum(1 for c in certs if c.get("status") == "expiring_soon"),
        "total_gaps": len(gaps),
        "severity_breakdown": severity_counts,
        "gap_type_breakdown": gap_type_counts,
    }

    # LLM enhancement: executive report
    reasoning_note = f"Report: {total} assets, {coverage:.1f}% encrypted, {len(gaps)} gaps found"
    try:
        from .prompts import (
            SYSTEM_ENCRYPTION_REPORT,
            EncryptionReportResult,
        )

        context = json.dumps(stats, default=str)
        llm_result = cast(
            EncryptionReportResult,
            await llm_structured(
                system_prompt=SYSTEM_ENCRYPTION_REPORT,
                user_prompt=(f"Encryption posture stats:\n{context}"),
                schema=EncryptionReportResult,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="data_encryption_monitor",
            node="report",
        )
        reasoning_note = f"{llm_result.executive_summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="data_encryption_monitor",
            node="report",
        )

    return {
        "stats": stats,
        "current_step": "report",
        "session_duration_ms": round(duration_ms, 2),
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning_note]),
    }


def _assess_algorithm_strength(algorithm: str) -> str:
    """Classify encryption algorithm strength."""
    if not algorithm:
        return "none"
    upper = algorithm.upper()
    if upper in {"AES-256", "CHACHA20", "TLS1.3"}:
        return "strong"
    if upper in {"AES-128", "TLS1.2"}:
        return "adequate"
    if upper in {"3DES", "DES", "RC4", "TLS1.1", "TLS1.0"}:
        return "weak"
    return "unknown"
