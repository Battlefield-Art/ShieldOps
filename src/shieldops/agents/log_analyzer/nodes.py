"""Node implementations for the Log Analyzer Agent LangGraph workflow."""

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.log_analyzer.models import (
    AnalyzerStage,
    AnomalySeverity,
    EventCorrelation,
    LogAnalyzerState,
    LogAnomaly,
    LogPattern,
    ReasoningStep,
)
from shieldops.agents.log_analyzer.prompts import (
    SYSTEM_ANOMALY_ANALYSIS,
    SYSTEM_CORRELATION,
    SYSTEM_REPORT,
    AnomalyAnalysisOutput,
    CorrelationOutput,
    ReportOutput,
)
from shieldops.agents.log_analyzer.tools import LogAnalyzerToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: LogAnalyzerToolkit | None = None


def _get_toolkit() -> LogAnalyzerToolkit:
    if _toolkit is None:
        return LogAnalyzerToolkit()
    return _toolkit


async def collect_logs(state: LogAnalyzerState) -> dict[str, Any]:
    """Collect log samples from configured sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    sources = [s.value for s in state.sources] if state.sources else ["application"]
    result = await toolkit.collect_log_samples(
        tenant_id=state.tenant_id,
        sources=sources,
        time_range_hours=state.time_range_hours,
    )

    samples = result.get("samples", [])
    total_count = result.get("total_count", 0)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="collect_logs",
        input_summary=f"Collecting from {len(sources)} sources, {state.time_range_hours}h window",
        output_summary=f"Collected {len(samples)} samples, {total_count} total logs",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="log_backend",
    )

    await toolkit.record_metric("logs_collected", float(total_count))

    return {
        "log_samples": samples,
        "total_log_count": total_count,
        "stage": AnalyzerStage.PARSE_PATTERNS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_logs",
        "session_start": start,
    }


async def parse_patterns(state: LogAnalyzerState) -> dict[str, Any]:
    """Parse collected logs to extract recurring patterns."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw_patterns = await toolkit.parse_patterns(state.log_samples)
    patterns = [LogPattern(**p) for p in raw_patterns if isinstance(p, dict)]
    error_count = sum(1 for p in patterns if p.is_error)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="parse_patterns",
        input_summary=f"Parsing {len(state.log_samples)} log samples",
        output_summary=f"Found {len(patterns)} patterns ({error_count} errors)",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="pattern_engine",
    )

    return {
        "patterns": patterns,
        "error_pattern_count": error_count,
        "stage": AnalyzerStage.DETECT_ANOMALIES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "parse_patterns",
    }


async def detect_anomalies(state: LogAnalyzerState) -> dict[str, Any]:
    """Detect anomalies by comparing patterns against baselines."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    pattern_dicts = [p.model_dump() for p in state.patterns]
    raw_anomalies = await toolkit.detect_anomalies(
        patterns=pattern_dicts,
        time_range_hours=state.time_range_hours,
    )
    anomalies = [LogAnomaly(**a) for a in raw_anomalies if isinstance(a, dict)]

    # LLM enhancement: deeper anomaly classification
    try:
        context = _json.dumps(
            {
                "tenant_id": state.tenant_id,
                "patterns": pattern_dicts[:20],
                "raw_anomaly_count": len(anomalies),
                "error_pattern_count": state.error_pattern_count,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ANOMALY_ANALYSIS,
            user_prompt=f"Log analysis context:\n{context}",
            schema=AnomalyAnalysisOutput,
        )
        logger.info(
            "llm_enhanced",
            node="detect_anomalies",
            severity=getattr(llm_result, "severity", "unknown"),
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="detect_anomalies")

    # Determine max severity
    severity_rank = {
        AnomalySeverity.CRITICAL: 4,
        AnomalySeverity.HIGH: 3,
        AnomalySeverity.MEDIUM: 2,
        AnomalySeverity.LOW: 1,
        AnomalySeverity.INFO: 0,
    }
    max_sev = AnomalySeverity.INFO
    for a in anomalies:
        if severity_rank.get(a.severity, 0) > severity_rank.get(max_sev, 0):
            max_sev = a.severity

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="detect_anomalies",
        input_summary=f"Analyzing {len(state.patterns)} patterns against baselines",
        output_summary=f"Detected {len(anomalies)} anomalies, max severity={max_sev}",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="anomaly_detector",
    )

    return {
        "anomalies": anomalies,
        "max_severity": max_sev,
        "stage": AnalyzerStage.CORRELATE_EVENTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_anomalies",
    }


async def correlate_events(state: LogAnalyzerState) -> dict[str, Any]:
    """Correlate anomalies across sources to find shared root causes."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    anomaly_dicts = [a.model_dump() for a in state.anomalies]
    raw_correlations = await toolkit.correlate_events(anomaly_dicts)
    correlations = [EventCorrelation(**c) for c in raw_correlations if isinstance(c, dict)]

    # LLM enhancement: deeper correlation analysis
    try:
        context = _json.dumps(
            {
                "tenant_id": state.tenant_id,
                "anomalies": anomaly_dicts[:15],
                "max_severity": state.max_severity,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CORRELATION,
            user_prompt=f"Anomaly correlation context:\n{context}",
            schema=CorrelationOutput,
        )
        if (
            hasattr(llm_result, "root_cause_hypothesis")
            and llm_result.root_cause_hypothesis
            and not correlations
        ):
            correlations.append(
                EventCorrelation(
                    id="llm-corr-001",
                    anomaly_ids=[a.id for a in state.anomalies[:5]],
                    correlation_type=getattr(llm_result, "correlation_type", "llm_inferred"),
                    description=getattr(llm_result, "reasoning", ""),
                    root_cause_hypothesis=llm_result.root_cause_hypothesis,
                    confidence=getattr(llm_result, "confidence", 0.5),
                )
            )
        logger.info("llm_enhanced", node="correlate_events")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="correlate_events")

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="correlate_events",
        input_summary=f"Correlating {len(state.anomalies)} anomalies",
        output_summary=f"Found {len(correlations)} correlations",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="correlation_engine",
    )

    return {
        "correlations": correlations,
        "stage": AnalyzerStage.ALERT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "correlate_events",
    }


async def send_alerts(state: LogAnalyzerState) -> dict[str, Any]:
    """Send alerts for high/critical anomalies."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    severity_rank = {
        AnomalySeverity.CRITICAL: 4,
        AnomalySeverity.HIGH: 3,
        AnomalySeverity.MEDIUM: 2,
        AnomalySeverity.LOW: 1,
        AnomalySeverity.INFO: 0,
    }

    alertable = [a for a in state.anomalies if severity_rank.get(a.severity, 0) >= 3]
    alerts_sent = 0
    channels: list[str] = []

    for anomaly in alertable:
        result = await toolkit.send_alert(
            tenant_id=state.tenant_id,
            severity=anomaly.severity,
            summary=anomaly.description or anomaly.anomaly_type,
            details={
                "anomaly_id": anomaly.id,
                "deviation_pct": anomaly.deviation_pct,
                "sample_logs": anomaly.sample_logs[:3],
            },
        )
        if result.get("sent"):
            alerts_sent += 1
            for ch in result.get("channels", []):
                if ch not in channels:
                    channels.append(ch)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="send_alerts",
        input_summary=f"{len(alertable)} alertable anomalies (high/critical)",
        output_summary=f"Sent {alerts_sent} alerts to {len(channels)} channels",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="alert_manager",
    )

    return {
        "alerts_sent": alerts_sent,
        "alert_channels": channels,
        "stage": AnalyzerStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "send_alerts",
    }


async def generate_report(state: LogAnalyzerState) -> dict[str, Any]:
    """Generate a final analysis report summarizing all findings."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    # Build report from available data
    parts = [
        f"Log Analysis Report — Tenant {state.tenant_id}",
        f"Time range: {state.time_range_hours}h",
        f"Total logs analyzed: {state.total_log_count}",
        f"Patterns identified: {len(state.patterns)} ({state.error_pattern_count} errors)",
        f"Anomalies detected: {len(state.anomalies)} (max severity: {state.max_severity})",
        f"Correlations found: {len(state.correlations)}",
        f"Alerts sent: {state.alerts_sent}",
    ]
    summary = ". ".join(parts)

    # LLM enhancement: generate executive summary
    try:
        context = _json.dumps(
            {
                "tenant_id": state.tenant_id,
                "total_logs": state.total_log_count,
                "pattern_count": len(state.patterns),
                "error_patterns": state.error_pattern_count,
                "anomaly_count": len(state.anomalies),
                "max_severity": state.max_severity,
                "correlations": [c.model_dump() for c in state.correlations[:10]],
                "alerts_sent": state.alerts_sent,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Full analysis context:\n{context}",
            schema=ReportOutput,
        )
        if hasattr(llm_result, "summary") and llm_result.summary:
            summary = llm_result.summary
        logger.info("llm_enhanced", node="generate_report")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="generate_report")

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    await toolkit.record_metric("analysis_duration_ms", float(duration_ms))

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary="Compiling final analysis report",
        output_summary=f"Report generated ({len(summary)} chars), duration={duration_ms}ms",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )

    return {
        "report_summary": summary,
        "session_duration_ms": duration_ms,
        "stage": AnalyzerStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
