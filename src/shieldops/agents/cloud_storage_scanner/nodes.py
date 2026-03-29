"""Cloud Storage Scanner Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import StorageBucket, StorageStage
from .tools import CloudStorageScannerToolkit

logger = structlog.get_logger()

_toolkit: CloudStorageScannerToolkit | None = None


def set_toolkit(
    toolkit: CloudStorageScannerToolkit,
) -> None:
    """Set the module-level toolkit for node functions."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> CloudStorageScannerToolkit:
    global _toolkit
    if _toolkit is None:
        _toolkit = CloudStorageScannerToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def discover_buckets(
    state: dict[str, Any],
    toolkit: CloudStorageScannerToolkit,
) -> dict[str, Any]:
    """Discover storage buckets across providers."""
    logger.info("css.node.discover")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "")
    providers = state.get("providers", ["s3"])

    buckets = await toolkit.discover_buckets(tenant_id, providers)
    buckets_data = [b.model_dump() for b in buckets]

    return {
        "stage": StorageStage.SCAN_ACCESS.value,
        "buckets": buckets_data,
        "current_step": "discover_buckets",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Discovered {len(buckets)} storage buckets across {', '.join(providers)}"],
    }


async def scan_access(
    state: dict[str, Any],
    toolkit: CloudStorageScannerToolkit,
) -> dict[str, Any]:
    """Scan bucket access configurations."""
    logger.info("css.node.access")
    state = _to_dict(state)

    raw_buckets = state.get("buckets", [])
    buckets = [StorageBucket(**b) for b in raw_buckets]

    findings = await toolkit.scan_access(buckets)
    findings_data = [f.model_dump() for f in findings]

    public_count = sum(1 for f in findings if f.public_readable)
    reasoning_note = f"Found {len(findings)} access issues, {public_count} publicly readable"

    try:
        from .prompts import (
            SYSTEM_ACCESS_ANALYSIS,
            AccessAnalysisOutput,
        )

        context = json.dumps(
            {
                "findings": len(findings),
                "public": public_count,
                "critical": sum(1 for f in findings if f.severity == "critical"),
            },
            default=str,
        )
        llm_result = cast(
            AccessAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_ACCESS_ANALYSIS,
                user_prompt=f"Access context:\n{context}",
                schema=AccessAnalysisOutput,
            ),
        )
        logger.info("llm_enhanced", agent="css", node="access")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="css", node="access")

    return {
        "stage": StorageStage.CHECK_ENCRYPTION.value,
        "access_findings": findings_data,
        "current_step": "scan_access",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def check_encryption(
    state: dict[str, Any],
    toolkit: CloudStorageScannerToolkit,
) -> dict[str, Any]:
    """Check bucket encryption configurations."""
    logger.info("css.node.encryption")
    state = _to_dict(state)

    raw_buckets = state.get("buckets", [])
    buckets = [StorageBucket(**b) for b in raw_buckets]

    findings = await toolkit.check_encryption(buckets)
    findings_data = [f.model_dump() for f in findings]

    reasoning_note = f"Found {len(findings)} encryption issues"

    try:
        from .prompts import (
            SYSTEM_ENCRYPTION_ANALYSIS,
            EncryptionAnalysisOutput,
        )

        context = json.dumps(
            {
                "issues": len(findings),
                "unencrypted": sum(1 for f in findings if f.encryption_type == "none"),
            },
            default=str,
        )
        llm_result = cast(
            EncryptionAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_ENCRYPTION_ANALYSIS,
                user_prompt=(f"Encryption context:\n{context}"),
                schema=EncryptionAnalysisOutput,
            ),
        )
        logger.info("llm_enhanced", agent="css", node="encryption")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="css", node="encryption")

    return {
        "stage": StorageStage.DETECT_SENSITIVE_DATA.value,
        "encryption_findings": findings_data,
        "current_step": "check_encryption",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def detect_sensitive_data(
    state: dict[str, Any],
    toolkit: CloudStorageScannerToolkit,
) -> dict[str, Any]:
    """Detect sensitive data in buckets."""
    logger.info("css.node.sensitive")
    state = _to_dict(state)

    raw_buckets = state.get("buckets", [])
    buckets = [StorageBucket(**b) for b in raw_buckets]

    findings = await toolkit.detect_sensitive_data(buckets)
    findings_data = [f.model_dump() for f in findings]

    return {
        "stage": StorageStage.ASSESS_RISK.value,
        "sensitive_data_findings": findings_data,
        "current_step": "detect_sensitive_data",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Detected sensitive data in {len(findings)} buckets"],
    }


async def assess_risk(
    state: dict[str, Any],
    toolkit: CloudStorageScannerToolkit,
) -> dict[str, Any]:
    """Assess overall storage security risk."""
    logger.info("css.node.risk")
    state = _to_dict(state)

    raw_buckets = state.get("buckets", [])
    raw_access = state.get("access_findings", [])
    raw_enc = state.get("encryption_findings", [])
    raw_sensitive = state.get("sensitive_data_findings", [])

    all_scores = [f.get("risk_score", 0.0) for f in raw_access] + [
        f.get("risk_score", 0.0) for f in raw_sensitive
    ]
    risk_score = round(max(all_scores) if all_scores else 0.0, 1)

    elapsed = round(
        (time.time() - state.get("session_start", time.time())) * 1000,
        1,
    )

    stats = {
        "buckets_scanned": len(raw_buckets),
        "access_findings": len(raw_access),
        "encryption_findings": len(raw_enc),
        "sensitive_data_findings": len(raw_sensitive),
        "risk_score": risk_score,
        "providers": state.get("providers", []),
    }

    report_summary = (
        f"Storage risk: {risk_score}/100."
        f" {len(raw_buckets)} buckets,"
        f" {len(raw_access)} access issues,"
        f" {len(raw_enc)} encryption issues,"
        f" {len(raw_sensitive)} sensitive data."
    )

    try:
        from .prompts import (
            SYSTEM_STORAGE_RISK,
            StorageRiskOutput,
        )

        context = json.dumps(stats, default=str)
        llm_result = cast(
            StorageRiskOutput,
            await llm_structured(
                system_prompt=SYSTEM_STORAGE_RISK,
                user_prompt=f"Storage context:\n{context}",
                schema=StorageRiskOutput,
            ),
        )
        logger.info("llm_enhanced", agent="css", node="risk")
        report_summary = llm_result.summary
    except Exception:
        logger.debug("llm_fallback", agent="css", node="risk")

    return {
        "stage": StorageStage.REPORT.value,
        "risk_score": risk_score,
        "stats": stats,
        "session_duration_ms": elapsed,
        "current_step": "assess_risk",
        "reasoning_chain": state.get("reasoning_chain", []) + [report_summary],
    }
