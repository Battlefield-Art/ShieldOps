"""Node implementations for the Forensic Evidence Chain."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.forensic_evidence_chain.models import (
    FECStage,
    ForensicEvidenceChainState,
    ReasoningStep,
)
from shieldops.agents.forensic_evidence_chain.prompts import (
    SYSTEM_CHAIN_CUSTODY,
    SYSTEM_COLLECT_EVIDENCE,
    SYSTEM_HASH_ARTIFACTS,
    SYSTEM_PACKAGE_LEGAL,
    SYSTEM_VALIDATE_INTEGRITY,
    CustodyChainOutput,
    EvidenceCollectionOutput,
    HashVerificationOutput,
    IntegrityOutput,
    PackagingOutput,
)
from shieldops.agents.forensic_evidence_chain.tools import (
    ForensicEvidenceChainToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ForensicEvidenceChainToolkit | None = None


def _get_toolkit() -> ForensicEvidenceChainToolkit:
    if _toolkit is None:
        return ForensicEvidenceChainToolkit()
    return _toolkit


def _step(
    state: ForensicEvidenceChainState,
    action: str,
    input_summary: str,
    output_summary: str,
    duration_ms: int,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Create a reasoning step."""
    return ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=duration_ms,
        tool_used=tool_used,
    )


async def collect_evidence(
    state: ForensicEvidenceChainState,
) -> dict[str, Any]:
    """Collect forensic evidence from configured sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.collect_evidence(state.config)

    try:
        ctx = _json.dumps(
            {
                "sources": state.config.get("sources", []),
                "item_count": len(raw),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_COLLECT_EVIDENCE,
            user_prompt=f"Evidence collection context:\n{ctx}",
            schema=EvidenceCollectionOutput,
        )
        if hasattr(llm_result, "total_items"):
            logger.info("llm_enhanced", node="collect_evidence")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="collect_evidence")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "collect_evidence",
        f"sources={state.config.get('sources', [])}",
        f"collected {len(raw)} evidence items",
        elapsed,
        "forensic_client",
    )
    await toolkit.record_metric("evidence_collected", float(len(raw)))

    return {
        "evidence_items": raw,
        "stage": FECStage.HASH_ARTIFACTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_evidence",
        "session_start": start,
    }


async def hash_artifacts(
    state: ForensicEvidenceChainState,
) -> dict[str, Any]:
    """Generate cryptographic hashes for evidence artifacts."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    hashes = await toolkit.hash_artifacts(state.evidence_items)

    try:
        ctx = _json.dumps(
            {
                "item_count": len(state.evidence_items),
                "hash_count": len(hashes),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_HASH_ARTIFACTS,
            user_prompt=f"Hash verification context:\n{ctx}",
            schema=HashVerificationOutput,
        )
        if hasattr(llm_result, "total_hashed"):
            logger.info("llm_enhanced", node="hash_artifacts")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="hash_artifacts")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "hash_artifacts",
        f"hashing {len(state.evidence_items)} items",
        f"{len(hashes)} hashes generated",
        elapsed,
        "hash_service",
    )

    return {
        "artifact_hashes": hashes,
        "stage": FECStage.CHAIN_CUSTODY,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "hash_artifacts",
    }


async def chain_custody(
    state: ForensicEvidenceChainState,
) -> dict[str, Any]:
    """Establish chain-of-custody records."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    records = await toolkit.chain_custody(state.evidence_items, state.config)

    try:
        ctx = _json.dumps(
            {
                "item_count": len(state.evidence_items),
                "record_count": len(records),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CHAIN_CUSTODY,
            user_prompt=f"Custody chain context:\n{ctx}",
            schema=CustodyChainOutput,
        )
        if hasattr(llm_result, "transfers"):
            logger.info("llm_enhanced", node="chain_custody")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="chain_custody")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "chain_custody",
        f"tracking {len(state.evidence_items)} items",
        f"{len(records)} custody records",
        elapsed,
        "forensic_client",
    )
    await toolkit.record_metric("custody_records", float(len(records)))

    return {
        "custody_records": records,
        "stage": FECStage.VALIDATE_INTEGRITY,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "chain_custody",
    }


async def validate_integrity(
    state: ForensicEvidenceChainState,
) -> dict[str, Any]:
    """Validate evidence integrity via hash re-verification."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.validate_integrity(state.artifact_hashes, state.custody_records)
    tampered = sum(1 for r in results if r.get("tamper_detected"))

    try:
        ctx = _json.dumps(
            {
                "hash_count": len(state.artifact_hashes),
                "result_count": len(results),
                "tampered": tampered,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_VALIDATE_INTEGRITY,
            user_prompt=f"Integrity validation context:\n{ctx}",
            schema=IntegrityOutput,
        )
        if hasattr(llm_result, "verified_count"):
            logger.info("llm_enhanced", node="validate_integrity")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="validate_integrity")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "validate_integrity",
        f"validating {len(state.artifact_hashes)} hashes",
        f"{len(results)} results, {tampered} tampered",
        elapsed,
        "hash_service",
    )

    return {
        "integrity_results": results,
        "stage": FECStage.PACKAGE_FOR_LEGAL,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "validate_integrity",
    }


async def package_for_legal(
    state: ForensicEvidenceChainState,
) -> dict[str, Any]:
    """Package validated evidence for legal proceedings."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    packages = await toolkit.package_for_legal(state.evidence_items, state.integrity_results)

    try:
        ctx = _json.dumps(
            {
                "item_count": len(state.evidence_items),
                "package_count": len(packages),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_PACKAGE_LEGAL,
            user_prompt=f"Legal packaging context:\n{ctx}",
            schema=PackagingOutput,
        )
        if hasattr(llm_result, "packages_created"):
            logger.info("llm_enhanced", node="package_for_legal")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="package_for_legal")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "package_for_legal",
        f"packaging {len(state.evidence_items)} items",
        f"{len(packages)} legal packages",
        elapsed,
        "storage_backend",
    )

    return {
        "legal_packages": packages,
        "stage": FECStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "package_for_legal",
    }


async def generate_report(
    state: ForensicEvidenceChainState,
) -> dict[str, Any]:
    """Generate final forensic evidence chain report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report = {
        "request_id": state.request_id,
        "evidence_items": len(state.evidence_items),
        "artifact_hashes": len(state.artifact_hashes),
        "custody_records": len(state.custody_records),
        "integrity_results": len(state.integrity_results),
        "legal_packages": len(state.legal_packages),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric("scan_duration_ms", float(duration_ms))

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "generate_report",
        f"finalizing {state.request_id}",
        f"report complete in {duration_ms}ms",
        elapsed,
        None,
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
