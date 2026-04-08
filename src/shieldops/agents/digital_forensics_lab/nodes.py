"""Node implementations for the Digital Forensics Lab
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.digital_forensics_lab.models import (
    DFLStage,
    DigitalForensicsLabState,
    ReasoningStep,
)
from shieldops.agents.digital_forensics_lab.prompts import (
    SYSTEM_ARTIFACTS,
    SYSTEM_IOCS,
    SYSTEM_REPORT,
    SYSTEM_TIMELINE,
    ArtifactAnalysisOutput,
    ForensicReportOutput,
    IOCExtractionOutput,
    TimelineConstructionOutput,
)
from shieldops.agents.digital_forensics_lab.tools import (
    DigitalForensicsLabToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: DigitalForensicsLabToolkit | None = None


def _get_toolkit() -> DigitalForensicsLabToolkit:
    if _toolkit is None:
        return DigitalForensicsLabToolkit()
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
# Node: acquire_evidence
# ------------------------------------------------------------------


async def acquire_evidence(
    state: DigitalForensicsLabState,
) -> dict[str, Any]:
    """Acquire digital evidence from target hosts with
    chain of custody tracking."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.acquire_evidence(
        target_hosts=state.target_hosts,
        evidence_types=state.evidence_types,
        case_id=state.case_id,
    )

    evidence: list[dict[str, Any]] = list(results)

    step = _step(
        state.reasoning_chain,
        "acquire_evidence",
        f"Acquiring from {len(state.target_hosts)} hosts",
        f"Collected {len(evidence)} evidence items",
        start,
        "evidence_acquirer",
    )

    return {
        "evidence": evidence,
        "total_evidence": len(evidence),
        "stage": DFLStage.ACQUIRE_EVIDENCE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "acquire_evidence",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: analyze_artifacts
# ------------------------------------------------------------------


async def analyze_artifacts(
    state: DigitalForensicsLabState,
) -> dict[str, Any]:
    """Analyze digital evidence for forensic artifacts
    across all evidence types."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    artifacts = await toolkit.analyze_artifacts(
        evidence=state.evidence,
        case_id=state.case_id,
    )

    artifacts_list: list[dict[str, Any]] = list(artifacts)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "evidence_count": len(state.evidence),
                "evidence_sample": state.evidence[:5],
                "case_id": state.case_id,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ARTIFACTS,
            user_prompt=(f"Analyze artifacts:\n{ctx}"),
            schema=ArtifactAnalysisOutput,
        )
        if llm_out.suspicious_items:  # type: ignore[union-attr]
            _rid = random.randint(1000, 9999)  # noqa: S311
            artifacts_list.append(
                {
                    "artifact_id": f"llm-{_rid}",
                    "categories": llm_out.categories,  # type: ignore[union-attr]
                    "suspicious_items": llm_out.suspicious_items,  # type: ignore[union-attr]
                    "confidence": llm_out.confidence,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="analyze_artifacts",
            suspicious=len(llm_out.suspicious_items),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_artifacts",
        )

    step = _step(
        state.reasoning_chain,
        "analyze_artifacts",
        f"Analyzing {len(state.evidence)} evidence items",
        f"Extracted {len(artifacts_list)} artifacts",
        start,
        "artifact_analyzer",
    )

    return {
        "artifacts": artifacts_list,
        "total_artifacts": len(artifacts_list),
        "stage": DFLStage.ANALYZE_ARTIFACTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_artifacts",
    }


# ------------------------------------------------------------------
# Node: extract_iocs
# ------------------------------------------------------------------


async def extract_iocs(
    state: DigitalForensicsLabState,
) -> dict[str, Any]:
    """Extract indicators of compromise from forensic
    artifacts and evidence."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    iocs = await toolkit.extract_iocs(
        artifacts=state.artifacts,
        evidence=state.evidence,
    )

    iocs_list: list[dict[str, Any]] = list(iocs)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "artifact_count": len(state.artifacts),
                "artifacts_sample": state.artifacts[:5],
                "evidence_count": len(state.evidence),
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_IOCS,
            user_prompt=f"Extract IOCs:\n{ctx}",
            schema=IOCExtractionOutput,
        )
        if llm_out.ioc_types:  # type: ignore[union-attr]
            _rid = random.randint(1000, 9999)  # noqa: S311
            iocs_list.append(
                {
                    "ioc_id": f"llm-{_rid}",
                    "ioc_types": llm_out.ioc_types,  # type: ignore[union-attr]
                    "mitre_mappings": llm_out.mitre_mappings,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="extract_iocs",
            types=len(llm_out.ioc_types),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="extract_iocs",
        )

    step = _step(
        state.reasoning_chain,
        "extract_iocs",
        f"Extracting from {len(state.artifacts)} artifacts",
        f"Extracted {len(iocs_list)} IOCs",
        start,
        "ioc_extractor",
    )

    return {
        "iocs": iocs_list,
        "total_iocs": len(iocs_list),
        "stage": DFLStage.EXTRACT_IOCS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "extract_iocs",
    }


# ------------------------------------------------------------------
# Node: build_timeline
# ------------------------------------------------------------------


async def build_timeline(
    state: DigitalForensicsLabState,
) -> dict[str, Any]:
    """Build forensic investigation timeline from all
    evidence sources, artifacts, and IOCs."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    timeline = await toolkit.build_timeline(
        artifacts=state.artifacts,
        iocs=state.iocs,
        evidence=state.evidence,
    )

    timeline_list: list[dict[str, Any]] = list(timeline)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "artifact_count": len(state.artifacts),
                "ioc_count": len(state.iocs),
                "evidence_count": len(state.evidence),
                "iocs_sample": state.iocs[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_TIMELINE,
            user_prompt=(f"Build timeline:\n{ctx}"),
            schema=TimelineConstructionOutput,
        )
        if llm_out.attack_phases:  # type: ignore[union-attr]
            _rid = random.randint(1000, 9999)  # noqa: S311
            timeline_list.append(
                {
                    "event_id": f"llm-{_rid}",
                    "attack_phases": llm_out.attack_phases,  # type: ignore[union-attr]
                    "pivot_points": llm_out.pivot_points,  # type: ignore[union-attr]
                    "narrative": llm_out.narrative,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="build_timeline",
            phases=len(llm_out.attack_phases),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="build_timeline",
        )

    step = _step(
        state.reasoning_chain,
        "build_timeline",
        (f"Building from {len(state.artifacts)} artifacts and {len(state.iocs)} IOCs"),
        f"Constructed {len(timeline_list)} events",
        start,
        "timeline_builder",
    )

    return {
        "timeline": timeline_list,
        "timeline_events": len(timeline_list),
        "stage": DFLStage.BUILD_TIMELINE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "build_timeline",
    }


# ------------------------------------------------------------------
# Node: generate_forensic_report
# ------------------------------------------------------------------


async def generate_forensic_report(
    state: DigitalForensicsLabState,
) -> dict[str, Any]:
    """Generate the final forensic investigation report
    with evidence integrity certification."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    forensic_report = await toolkit.generate_forensic_report(
        timeline=state.timeline,
        iocs=state.iocs,
        artifacts=state.artifacts,
        case_id=state.case_id,
    )

    report: dict[str, Any] = {
        **forensic_report,
        "total_evidence": state.total_evidence,
        "total_artifacts": state.total_artifacts,
        "total_iocs": state.total_iocs,
        "timeline_events": state.timeline_events,
        "duration_ms": duration_ms,
    }

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "case_id": state.case_id,
                "incident_id": state.incident_id,
                "total_evidence": state.total_evidence,
                "total_artifacts": state.total_artifacts,
                "total_iocs": state.total_iocs,
                "timeline_events": state.timeline_events,
                "iocs_sample": state.iocs[:5],
                "timeline_sample": state.timeline[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate forensic report:\n{ctx}"),
            schema=ForensicReportOutput,
        )
        if isinstance(llm_out, ForensicReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "attack_vector": llm_out.attack_vector,
                    "recommendations": llm_out.recommendations,
                    "evidence_integrity": llm_out.evidence_integrity,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_forensic_report",
                recs=len(llm_out.recommendations),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_forensic_report",
        )

    await toolkit.record_metric(
        metric_name="forensics_case",
        value=float(state.total_iocs),
        labels={"case": state.case_id},
    )

    step = _step(
        state.reasoning_chain,
        "generate_forensic_report",
        f"Reporting on case {state.case_id}",
        "Forensic report generated",
        start,
        "report_generator",
    )

    return {
        "forensic_report": forensic_report,
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": DFLStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
