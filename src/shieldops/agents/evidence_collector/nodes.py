"""Node implementations for the Evidence Collector Agent."""

from __future__ import annotations

import json as _json
import time
from typing import Any

import structlog

from shieldops.agents.evidence_collector.models import (
    EvidenceCollectorState,
    EvidenceStage,
)
from shieldops.agents.evidence_collector.prompts import (
    SYSTEM_IDENTIFY_SOURCES,
    SYSTEM_PACKAGE,
    SYSTEM_REPORT,
    SYSTEM_VERIFY_INTEGRITY,
    IntegrityOutput,
    PackageOutput,
    ReportOutput,
    SourceIdentOutput,
)
from shieldops.agents.evidence_collector.tools import (
    EvidenceCollectorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: EvidenceCollectorToolkit | None = None


def set_toolkit(
    toolkit: EvidenceCollectorToolkit,
) -> None:
    """Set the toolkit instance for node functions."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> EvidenceCollectorToolkit:
    if _toolkit is None:
        return EvidenceCollectorToolkit()
    return _toolkit


async def identify_sources(
    state: EvidenceCollectorState,
) -> dict[str, Any]:
    """Identify evidence sources relevant to the incident."""
    toolkit = _get_toolkit()

    incident_details = state.incident_details or {
        "type": "default",
        "affected_hosts": ["unknown-host"],
        "incident_id": state.incident_id,
    }

    sources = await toolkit.identify_sources(incident_details)

    # LLM-enhanced source prioritization
    try:
        context = _json.dumps(
            {
                "incident_id": state.incident_id,
                "incident_details": incident_details,
                "sources_found": len(sources),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_IDENTIFY_SOURCES,
            user_prompt=(f"Identify and prioritize evidence sources for this incident:\n{context}"),
            schema=SourceIdentOutput,
        )
        logger.info(
            "llm_enhanced",
            node="identify_sources",
            reasoning=llm_result.reasoning[:80],
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="identify_sources",
        )

    reasoning = [
        *state.reasoning_chain,
        f"Identified {len(sources)} evidence sources for incident {state.incident_id}",
    ]

    return {
        "sources": sources,
        "stage": EvidenceStage.COLLECT_ARTIFACTS,
        "reasoning_chain": reasoning,
        "session_start": state.session_start or time.time(),
    }


async def collect_artifacts(
    state: EvidenceCollectorState,
) -> dict[str, Any]:
    """Collect forensic artifacts from identified sources."""
    toolkit = _get_toolkit()

    artifacts = []
    for source in state.sources:
        artifact = await toolkit.collect_artifact(source)
        artifacts.append(artifact)

    reasoning = [
        *state.reasoning_chain,
        f"Collected {len(artifacts)} artifacts from {len(state.sources)} sources",
    ]

    return {
        "artifacts": artifacts,
        "stage": EvidenceStage.HASH_VERIFY,
        "reasoning_chain": reasoning,
    }


async def hash_verify(
    state: EvidenceCollectorState,
) -> dict[str, Any]:
    """Verify integrity of collected artifacts via hashing."""
    toolkit = _get_toolkit()

    verifications = []
    verified_count = 0
    for artifact in state.artifacts:
        verification = await toolkit.verify_integrity(artifact)
        verifications.append(verification)
        if verification.hash_verified:
            verified_count += 1

    # LLM-enhanced integrity assessment
    try:
        context = _json.dumps(
            {
                "total_artifacts": len(state.artifacts),
                "verified": verified_count,
                "failed": len(state.artifacts) - verified_count,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_VERIFY_INTEGRITY,
            user_prompt=(f"Assess the integrity of these forensic artifacts:\n{context}"),
            schema=IntegrityOutput,
        )
        logger.info(
            "llm_enhanced",
            node="hash_verify",
            status=llm_result.status,
            confidence=llm_result.confidence,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="hash_verify",
        )

    reasoning = [
        *state.reasoning_chain,
        f"Verified {verified_count}/{len(state.artifacts)} artifacts passed integrity check",
    ]

    return {
        "verifications": verifications,
        "verified_count": verified_count,
        "stage": EvidenceStage.CHAIN_OF_CUSTODY,
        "reasoning_chain": reasoning,
    }


async def chain_of_custody(
    state: EvidenceCollectorState,
) -> dict[str, Any]:
    """Record chain-of-custody entries for all artifacts."""
    toolkit = _get_toolkit()

    custody_records = []
    for artifact in state.artifacts:
        record = await toolkit.record_custody(
            artifact_id=artifact.id,
            custodian="evidence_collector_agent",
            action="collected_and_verified",
            purpose=(f"Forensic evidence for incident {state.incident_id}"),
        )
        custody_records.append(record)

    reasoning = [
        *state.reasoning_chain,
        f"Recorded {len(custody_records)} chain-of-custody "
        f"entries for incident {state.incident_id}",
    ]

    return {
        "custody_records": custody_records,
        "stage": EvidenceStage.PACKAGE_EVIDENCE,
        "reasoning_chain": reasoning,
    }


async def package_evidence(
    state: EvidenceCollectorState,
) -> dict[str, Any]:
    """Package all artifacts into a sealed evidence bundle."""
    toolkit = _get_toolkit()

    package = await toolkit.package_evidence(
        incident_id=state.incident_id,
        artifacts=state.artifacts,
    )

    # LLM-enhanced packaging classification
    try:
        context = _json.dumps(
            {
                "incident_id": state.incident_id,
                "artifact_count": len(state.artifacts),
                "verified_count": state.verified_count,
                "package_id": package.id,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_PACKAGE,
            user_prompt=(f"Classify and label this evidence package:\n{context}"),
            schema=PackageOutput,
        )
        logger.info(
            "llm_enhanced",
            node="package_evidence",
            classification=llm_result.classification,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="package_evidence",
        )

    reasoning = [
        *state.reasoning_chain,
        f"Packaged {len(state.artifacts)} artifacts into package {package.id}",
    ]

    return {
        "package": package.model_dump(),
        "stage": EvidenceStage.REPORT,
        "reasoning_chain": reasoning,
    }


async def report(
    state: EvidenceCollectorState,
) -> dict[str, Any]:
    """Generate the final evidence collection report."""
    duration_ms = 0
    if state.session_start:
        duration_ms = int((time.time() - state.session_start) * 1000)

    report_data: dict[str, Any] = {
        "incident_id": state.incident_id,
        "tenant_id": state.tenant_id,
        "sources_identified": len(state.sources),
        "artifacts_collected": len(state.artifacts),
        "artifacts_verified": state.verified_count,
        "custody_records": len(state.custody_records),
        "package": state.package,
        "integrity_status": (
            "all_verified" if state.verified_count == len(state.artifacts) else "partial"
        ),
        "chain_of_custody_complete": (len(state.custody_records) == len(state.artifacts)),
        "duration_ms": duration_ms,
        "status": "complete",
    }

    # LLM-enhanced report summary
    try:
        context = _json.dumps(report_data, default=str)
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate the evidence collection report:\n{context}"),
            schema=ReportOutput,
        )
        report_data["executive_summary"] = llm_result.executive_summary
        report_data["integrity_status"] = llm_result.integrity_status
        report_data["chain_of_custody_complete"] = llm_result.chain_of_custody_complete
        report_data["recommendations"] = llm_result.recommendations
        logger.info(
            "llm_enhanced",
            node="report",
            artifacts=llm_result.artifacts_collected,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="report",
        )

    reasoning = [
        *state.reasoning_chain,
        f"Generated report: {len(state.artifacts)} artifacts, "
        f"{state.verified_count} verified, "
        f"duration={duration_ms}ms",
    ]

    return {
        "report": report_data,
        "stage": "complete",
        "reasoning_chain": reasoning,
    }
