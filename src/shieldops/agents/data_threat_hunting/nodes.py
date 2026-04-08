"""Node implementations for the Data Threat Hunting Agent."""

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.data_threat_hunting.models import (
    DataThreatHuntingState,
    HuntSource,
    HuntStage,
    ReasoningStep,
    ThreatVerdict,
)
from shieldops.agents.data_threat_hunting.prompts import (
    SYSTEM_CORRELATION,
    SYSTEM_HUNT_REPORT,
    SYSTEM_HYPOTHESIS_GENERATION,
    SYSTEM_INDICATOR_ANALYSIS,
    CorrelationOutput,
    HuntReportOutput,
    HypothesisGenerationOutput,
    IndicatorAnalysisOutput,
)
from shieldops.agents.data_threat_hunting.tools import (
    DataThreatHuntingToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: DataThreatHuntingToolkit | None = None


def _get_toolkit() -> DataThreatHuntingToolkit:
    if _toolkit is None:
        return DataThreatHuntingToolkit()
    return _toolkit


async def generate_hypotheses(
    state: DataThreatHuntingState,
) -> dict[str, Any]:
    """Generate hunt hypotheses from threat intel and context."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.generate_hypotheses(
        context=state.hunt_scope,
        initial_hypotheses=state.initial_hypotheses,
    )

    # LLM enhancement: refine hypotheses with reasoning
    try:
        ctx = _json.dumps(
            {
                "initial_hypotheses": state.initial_hypotheses,
                "hunt_scope": state.hunt_scope,
                "target_sources": state.target_sources,
                "raw_hypotheses": raw[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_HYPOTHESIS_GENERATION,
            user_prompt=(f"Generate hunt hypotheses:\n{ctx}"),
            schema=HypothesisGenerationOutput,
        )
        if hasattr(llm_result, "hypotheses"):
            enriched = getattr(llm_result, "hypotheses", [])
            if enriched:
                raw = enriched
        logger.info(
            "llm_enhanced",
            node="generate_hypotheses",
            hypothesis_count=len(raw),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_hypotheses",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_hypotheses",
        input_summary=(f"Initial hypotheses: {len(state.initial_hypotheses)}"),
        output_summary=(f"Generated {len(raw)} hunt hypotheses"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="threat_intel",
    )

    return {
        "hypotheses": raw,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": HuntStage.generate_hypotheses,
        "session_start": start,
    }


async def collect_evidence(
    state: DataThreatHuntingState,
) -> dict[str, Any]:
    """Collect evidence from all target data sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    sources = state.target_sources or [
        HuntSource.production,
        HuntSource.backup_snapshot,
    ]

    all_evidence: list[dict[str, Any]] = []
    for source in sources:
        result = await toolkit.collect_evidence(
            source_type=source,
            scope=state.hunt_scope,
        )
        all_evidence.append(result)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="collect_evidence",
        input_summary=(f"Collecting from {len(sources)} sources"),
        output_summary=(f"Collected evidence from {len(all_evidence)} sources"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="evidence_collector",
    )

    return {
        "evidence": all_evidence,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": HuntStage.collect_evidence,
    }


async def analyze_indicators(
    state: DataThreatHuntingState,
) -> dict[str, Any]:
    """Analyze collected evidence for IOC matches and patterns."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    ioc_feeds = state.hunt_scope.get("ioc_feeds")
    indicators = await toolkit.analyze_indicators(
        evidence=state.evidence,
        ioc_feeds=ioc_feeds,
    )

    # LLM enhancement: deeper indicator analysis
    try:
        ctx = _json.dumps(
            {
                "evidence_count": len(state.evidence),
                "indicators_raw": indicators[:20],
                "hypotheses": [h.get("description", "") for h in state.hypotheses[:5]],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_INDICATOR_ANALYSIS,
            user_prompt=(f"Analyze these indicators:\n{ctx}"),
            schema=IndicatorAnalysisOutput,
        )
        if hasattr(llm_result, "behavioral_patterns"):
            patterns = getattr(llm_result, "behavioral_patterns", [])
            for pattern in patterns:
                indicators.append(
                    {
                        "indicator_type": "behavioral",
                        "indicator_value": pattern,
                        "matched": True,
                        "match_source": "llm_analysis",
                        "severity": getattr(llm_result, "severity", "medium"),
                        "behavioral_pattern": pattern,
                    }
                )
        logger.info(
            "llm_enhanced",
            node="analyze_indicators",
            indicator_count=len(indicators),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_indicators",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="analyze_indicators",
        input_summary=(f"Analyzing {len(state.evidence)} evidence collections"),
        output_summary=(f"Found {len(indicators)} indicators"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="ioc_scanner",
    )

    return {
        "indicators": indicators,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": HuntStage.analyze_indicators,
    }


async def hunt_in_backups(
    state: DataThreatHuntingState,
) -> dict[str, Any]:
    """Scan backup snapshots for dormant threats."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    snapshot_ids = state.hunt_scope.get("snapshot_ids", ["latest"])
    scan_config = {
        "source_system": state.hunt_scope.get("source_system", "production-db"),
        "scan_depth": state.hunt_scope.get("scan_depth", "standard"),
        "check_ransomware": True,
        "check_persistence": True,
        "check_exfiltration": True,
    }

    scans: list[dict[str, Any]] = []
    for snap_id in snapshot_ids:
        result = await toolkit.scan_backup_snapshot(
            snapshot_id=snap_id,
            scan_config=scan_config,
        )
        scans.append(result)

    total_threats = sum(s.get("threats_found", 0) for s in scans)
    ransomware_found = any(s.get("ransomware_staging") for s in scans)
    persistence_found = any(s.get("persistence_detected") for s in scans)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="hunt_in_backups",
        input_summary=(f"Scanning {len(snapshot_ids)} backup snapshots"),
        output_summary=(
            f"Scanned {len(scans)} snapshots, "
            f"{total_threats} threats, "
            f"ransomware={ransomware_found}, "
            f"persistence={persistence_found}"
        ),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="backup_scanner",
    )

    return {
        "backup_scans": scans,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": HuntStage.hunt_in_backups,
    }


async def correlate_findings(
    state: DataThreatHuntingState,
) -> dict[str, Any]:
    """Correlate findings across all sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw_correlated = await toolkit.correlate_cross_source(
        findings=state.indicators,
        evidence=state.evidence,
        backup_scans=state.backup_scans,
    )

    # LLM enhancement: deeper correlation reasoning
    try:
        ctx = _json.dumps(
            {
                "indicators": state.indicators[:20],
                "evidence_sources": [e.get("source", "") for e in state.evidence],
                "backup_results": state.backup_scans[:10],
                "hypotheses": [h.get("description", "") for h in state.hypotheses[:5]],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CORRELATION,
            user_prompt=(f"Correlate these findings:\n{ctx}"),
            schema=CorrelationOutput,
        )
        if hasattr(llm_result, "findings"):
            llm_findings = getattr(llm_result, "findings", [])
            if llm_findings:
                raw_correlated = llm_findings
        threats_confirmed = getattr(llm_result, "threats_confirmed", 0)
        logger.info(
            "llm_enhanced",
            node="correlate_findings",
            finding_count=len(raw_correlated),
        )
    except Exception:
        threats_confirmed = sum(
            1 for f in raw_correlated if f.get("verdict") == ThreatVerdict.confirmed_threat
        )
        logger.debug(
            "llm_enhancement_skipped",
            node="correlate_findings",
        )

    # Fallback threat count from backup scans
    if threats_confirmed == 0:
        threats_confirmed = sum(s.get("threats_found", 0) for s in state.backup_scans)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="correlate_findings",
        input_summary=(
            f"Correlating {len(state.indicators)} "
            f"indicators + {len(state.backup_scans)} "
            f"backup scans"
        ),
        output_summary=(
            f"Produced {len(raw_correlated)} correlated findings, {threats_confirmed} confirmed"
        ),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="signal_correlator",
    )

    return {
        "findings": raw_correlated,
        "threats_confirmed": threats_confirmed,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": HuntStage.correlate_findings,
    }


async def report(
    state: DataThreatHuntingState,
) -> dict[str, Any]:
    """Generate the final hunt report with playbook."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_secs = 0.0
    if state.session_start:
        duration_secs = (datetime.now(UTC) - state.session_start).total_seconds()

    # Generate playbook
    playbook = await toolkit.generate_hunt_playbook(
        findings=state.findings,
        hypotheses=state.hypotheses,
    )

    # Build base report
    hunt_report: dict[str, Any] = {
        "hunt_id": state.hunt_id,
        "tenant_id": state.tenant_id,
        "hypotheses_tested": len(state.hypotheses),
        "sources_queried": len(state.evidence),
        "backups_scanned": len(state.backup_scans),
        "indicators_found": len(state.indicators),
        "findings_count": len(state.findings),
        "threats_confirmed": state.threats_confirmed,
        "hunt_duration_seconds": duration_secs,
        "playbook": playbook,
    }

    # LLM enhancement: executive report
    try:
        ctx = _json.dumps(
            {
                "findings": state.findings[:20],
                "indicators": state.indicators[:20],
                "backup_scans": state.backup_scans[:10],
                "hypotheses": [h.get("description", "") for h in state.hypotheses[:5]],
                "threats_confirmed": (state.threats_confirmed),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_HUNT_REPORT,
            user_prompt=(f"Generate hunt report:\n{ctx}"),
            schema=HuntReportOutput,
        )
        if hasattr(llm_result, "executive_summary"):
            hunt_report["executive_summary"] = getattr(
                llm_result,
                "executive_summary",
                "",
            )
            hunt_report["threat_level"] = getattr(llm_result, "threat_level", "low")
            hunt_report["key_findings"] = getattr(llm_result, "key_findings", [])
            hunt_report["recommended_actions"] = getattr(
                llm_result,
                "recommended_actions",
                [],
            )
            hunt_report["hunt_playbook"] = getattr(llm_result, "hunt_playbook", [])
        logger.info(
            "llm_enhanced",
            node="report",
            threat_level=hunt_report.get("threat_level", "unknown"),
        )
    except Exception:
        hunt_report["executive_summary"] = (
            f"Hunt completed: {state.threats_confirmed} "
            f"threats confirmed across "
            f"{len(state.evidence)} sources."
        )
        hunt_report["threat_level"] = (
            "critical"
            if state.threats_confirmed >= 3
            else "high"
            if state.threats_confirmed >= 1
            else "low"
        )
        logger.debug(
            "llm_enhancement_skipped",
            node="report",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="report",
        input_summary=(f"Generating report for {len(state.findings)} findings"),
        output_summary=(
            f"Report generated, threat_level={hunt_report.get('threat_level', 'unknown')}"
        ),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )

    return {
        "hunt_report": hunt_report,
        "hunt_duration_seconds": duration_secs,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": HuntStage.complete,
    }
