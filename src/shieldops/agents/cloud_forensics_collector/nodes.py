"""Node implementations for the Cloud Forensics
Collector Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.cloud_forensics_collector.models import (
    CFCStage,
    CloudForensicsCollectorState,
    ReasoningStep,
)
from shieldops.agents.cloud_forensics_collector.prompts import (
    SYSTEM_ANALYSIS,
    SYSTEM_PRESERVATION,
    SYSTEM_REPORT,
    SYSTEM_SCOPE,
    EvidencePreservationOutput,
    ForensicReportOutput,
    LogAnalysisOutput,
    ScopeIdentificationOutput,
)
from shieldops.agents.cloud_forensics_collector.tools import (
    CloudForensicsCollectorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: CloudForensicsCollectorToolkit | None = None


def _get_toolkit() -> CloudForensicsCollectorToolkit:
    if _toolkit is None:
        return CloudForensicsCollectorToolkit()
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
# Node: identify_scope
# ------------------------------------------------------------------


async def identify_scope(
    state: CloudForensicsCollectorState,
) -> dict[str, Any]:
    """Identify the forensic investigation scope from
    incident context and cloud resources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    forensic_scope = await toolkit.identify_scope(
        incident_id=state.incident_id,
        cloud_provider=state.cloud_provider.value,
        target_resources=state.target_resources,
        time_range=state.time_range,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "case_name": state.case_name,
                "incident_id": state.incident_id,
                "provider": state.cloud_provider.value,
                "resources": state.target_resources,
                "time_range": state.time_range,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_SCOPE,
            user_prompt=f"Identify scope for:\n{ctx}",
            schema=ScopeIdentificationOutput,
        )
        if llm_out.resources:  # type: ignore[union-attr]
            forensic_scope.update(
                {
                    "llm_resources": llm_out.resources,  # type: ignore[union-attr]
                    "evidence_types": llm_out.evidence_types,  # type: ignore[union-attr]
                    "priority": llm_out.priority_resources,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="identify_scope",
            resources=len(llm_out.resources),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="identify_scope",
        )

    step = _step(
        state.reasoning_chain,
        "identify_scope",
        f"Incident: {state.incident_id}, provider={state.cloud_provider}",
        "Forensic scope identified",
        start,
        "scope_identifier",
    )

    return {
        "forensic_scope": forensic_scope,
        "stage": CFCStage.IDENTIFY_SCOPE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "identify_scope",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: collect_logs
# ------------------------------------------------------------------


async def collect_logs(
    state: CloudForensicsCollectorState,
) -> dict[str, Any]:
    """Collect cloud audit logs from the scoped
    providers and time window."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logs = await toolkit.collect_cloud_logs(
        forensic_scope=state.forensic_scope,
        cloud_provider=state.cloud_provider.value,
    )

    step = _step(
        state.reasoning_chain,
        "collect_logs",
        f"Collecting from {state.cloud_provider.value}",
        f"Collected {len(logs)} log records",
        start,
        "log_collector",
    )

    return {
        "collected_logs": logs,
        "stage": CFCStage.COLLECT_LOGS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_logs",
    }


# ------------------------------------------------------------------
# Node: capture_snapshots
# ------------------------------------------------------------------


async def capture_snapshots(
    state: CloudForensicsCollectorState,
) -> dict[str, Any]:
    """Capture disk snapshots and memory dumps for
    target resources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    snapshots = await toolkit.capture_snapshots(
        forensic_scope=state.forensic_scope,
        target_resources=state.target_resources,
    )

    step = _step(
        state.reasoning_chain,
        "capture_snapshots",
        f"Capturing {len(state.target_resources)} resources",
        f"Captured {len(snapshots)} snapshots",
        start,
        "snapshot_capturer",
    )

    return {
        "snapshots": snapshots,
        "stage": CFCStage.CAPTURE_SNAPSHOTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "capture_snapshots",
    }


# ------------------------------------------------------------------
# Node: preserve_evidence
# ------------------------------------------------------------------


async def preserve_evidence(
    state: CloudForensicsCollectorState,
) -> dict[str, Any]:
    """Preserve all collected evidence with chain of
    custody and integrity verification."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    preserved = await toolkit.preserve_evidence(
        logs=state.collected_logs,
        snapshots=state.snapshots,
    )

    preserved_list: list[dict[str, Any]] = list(preserved)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "log_count": len(state.collected_logs),
                "snapshot_count": len(state.snapshots),
                "case_name": state.case_name,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_PRESERVATION,
            user_prompt=f"Verify preservation:\n{ctx}",
            schema=EvidencePreservationOutput,
        )
        custody_valid = (
            llm_out.preserved  # type: ignore[union-attr]
            and llm_out.integrity_verified  # type: ignore[union-attr]
        )
        if llm_out.chain_of_custody:  # type: ignore[union-attr]
            rand_id = random.randint(1000, 9999)  # noqa: S311
            preserved_list.append(
                {
                    "evidence_id": f"llm-{rand_id}",
                    "custody": llm_out.chain_of_custody,  # type: ignore[union-attr]
                    "storage": llm_out.storage_details,  # type: ignore[union-attr]
                    "integrity_valid": custody_valid,
                }
            )
        logger.info(
            "llm_enhanced",
            node="preserve_evidence",
            custody_valid=custody_valid,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="preserve_evidence",
        )

    total = len(state.collected_logs) + len(state.snapshots)

    step = _step(
        state.reasoning_chain,
        "preserve_evidence",
        f"Preserving {total} evidence items",
        f"Preserved {len(preserved_list)} records",
        start,
        "evidence_preserver",
    )

    return {
        "preserved_evidence": preserved_list,
        "total_evidence": len(preserved_list),
        "stage": CFCStage.PRESERVE_EVIDENCE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "preserve_evidence",
    }


# ------------------------------------------------------------------
# Node: analyze_evidence
# ------------------------------------------------------------------


async def analyze_evidence(
    state: CloudForensicsCollectorState,
) -> dict[str, Any]:
    """Analyze preserved evidence for IOCs and attack
    timeline reconstruction."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    analysis = await toolkit.analyze_evidence(
        preserved=state.preserved_evidence,
        forensic_scope=state.forensic_scope,
    )

    analysis_list: list[dict[str, Any]] = list(analysis)
    iocs_found = 0

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "evidence_count": state.total_evidence,
                "evidence_sample": state.preserved_evidence[:5],
                "scope": state.forensic_scope,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ANALYSIS,
            user_prompt=f"Analyze evidence:\n{ctx}",
            schema=LogAnalysisOutput,
        )
        if llm_out.iocs:  # type: ignore[union-attr]
            rand_id = random.randint(1000, 9999)  # noqa: S311
            analysis_list.append(
                {
                    "analysis_id": f"llm-{rand_id}",
                    "suspicious_events": llm_out.suspicious_events,  # type: ignore[union-attr]
                    "iocs": llm_out.iocs,  # type: ignore[union-attr]
                    "timeline": llm_out.timeline,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
            iocs_found = len(llm_out.iocs)  # type: ignore[union-attr]
        logger.info(
            "llm_enhanced",
            node="analyze_evidence",
            iocs=iocs_found,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_evidence",
        )

    severity = "critical" if iocs_found > 5 else ("high" if iocs_found > 2 else "medium")

    step = _step(
        state.reasoning_chain,
        "analyze_evidence",
        f"Analyzing {state.total_evidence} evidence items",
        f"Found {iocs_found} IOCs, severity={severity}",
        start,
        "forensic_analyzer",
    )

    return {
        "analysis": analysis_list,
        "iocs_found": iocs_found,
        "severity": severity,
        "stage": CFCStage.ANALYZE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_evidence",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: CloudForensicsCollectorState,
) -> dict[str, Any]:
    """Generate the final forensic investigation report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report = await toolkit.generate_report(
        forensic_scope=state.forensic_scope,
        analysis=state.analysis,
        evidence_count=state.total_evidence,
        iocs_found=state.iocs_found,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "case_name": state.case_name,
                "incident_id": state.incident_id,
                "provider": state.cloud_provider.value,
                "total_evidence": state.total_evidence,
                "iocs_found": state.iocs_found,
                "severity": state.severity,
                "analysis_sample": state.analysis[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate forensic report:\n{ctx}",
            schema=ForensicReportOutput,
        )
        if isinstance(llm_out, ForensicReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "attack_timeline": llm_out.attack_timeline,
                    "recommendations": llm_out.recommendations,
                    "severity_rating": llm_out.severity_rating,
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
    await toolkit.record_metric(
        "forensics_iocs_found",
        float(state.iocs_found),
        {"case": state.case_name},
    )

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.total_evidence} evidence items",
        f"Report generated, IOCs={state.iocs_found}",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": CFCStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
