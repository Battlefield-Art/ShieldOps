"""Node implementations for the Log Anomaly Detector."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.log_anomaly_detector.models import (
    LADStage,
    LogAnomalyDetectorState,
    ReasoningStep,
)
from shieldops.agents.log_anomaly_detector.prompts import (
    SYSTEM_CORRELATE,
    SYSTEM_DETECT,
    SYSTEM_INGEST,
    SYSTEM_PARSE,
    SYSTEM_PRIORITIZE,
    AnomalyDetectionOutput,
    CorrelationOutput,
    LogIngestionOutput,
    PatternParseOutput,
    PrioritizationOutput,
)
from shieldops.agents.log_anomaly_detector.tools import (
    LogAnomalyDetectorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: LogAnomalyDetectorToolkit | None = None


def set_toolkit(
    toolkit: LogAnomalyDetectorToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> LogAnomalyDetectorToolkit:
    if _toolkit is None:
        return LogAnomalyDetectorToolkit()
    return _toolkit


def _step(
    state: LogAnomalyDetectorState,
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


async def ingest_logs(
    state: LogAnomalyDetectorState,
) -> dict[str, Any]:
    """Ingest log data from configured sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    batches = await toolkit.ingest_logs(state.detect_config)
    total = sum(b.get("record_count", 0) for b in batches)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "sources": state.detect_config.get(
                    "sources",
                    [],
                )[:10],
                "batch_count": len(batches),
                "total_records": total,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_INGEST,
            user_prompt=(f"Log ingestion context:\n{ctx}"),
            schema=LogIngestionOutput,
        )
        if hasattr(llm_result, "total_records") and llm_result.total_records > total:
            total = llm_result.total_records
        logger.info(
            "llm_enhanced",
            node="ingest_logs",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="ingest_logs",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "ingest_logs",
        f"sources={state.detect_config.get('sources', [])}",
        f"ingested {total} records in {len(batches)} batches",
        elapsed,
        "log_client",
    )
    await toolkit.record_metric("ingestion", float(total))

    return {
        "ingested_logs": batches,
        "total_records": total,
        "stage": LADStage.PARSE_PATTERNS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "ingest_logs",
        "session_start": start,
    }


async def parse_patterns(
    state: LogAnomalyDetectorState,
) -> dict[str, Any]:
    """Extract patterns from ingested logs."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    patterns = await toolkit.parse_patterns(
        state.ingested_logs,
    )
    new_count = sum(1 for p in patterns if p.get("is_new"))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "batch_count": len(state.ingested_logs),
                "pattern_count": len(patterns),
                "new_patterns": new_count,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_PARSE,
            user_prompt=(f"Pattern analysis context:\n{ctx}"),
            schema=PatternParseOutput,
        )
        if hasattr(llm_result, "new_patterns") and llm_result.new_patterns > new_count:
            new_count = llm_result.new_patterns
        logger.info(
            "llm_enhanced",
            node="parse_patterns",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="parse_patterns",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "parse_patterns",
        f"parsing {len(state.ingested_logs)} batches",
        f"{len(patterns)} patterns, {new_count} new",
        elapsed,
        "pattern_engine",
    )

    return {
        "log_patterns": patterns,
        "new_pattern_count": new_count,
        "stage": LADStage.DETECT_ANOMALIES,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "parse_patterns",
    }


async def detect_anomalies(
    state: LogAnomalyDetectorState,
) -> dict[str, Any]:
    """Detect anomalies in log patterns."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    anomalies = await toolkit.detect_anomalies(
        state.log_patterns,
    )
    max_score = max(
        (a.get("confidence", 0.0) for a in anomalies),
        default=0.0,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "pattern_count": len(state.log_patterns),
                "anomalies": anomalies[:10],
                "max_confidence": max_score,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_DETECT,
            user_prompt=(f"Anomaly detection context:\n{ctx}"),
            schema=AnomalyDetectionOutput,
        )
        if hasattr(llm_result, "max_confidence") and llm_result.max_confidence > max_score:
            max_score = round(
                (max_score + llm_result.max_confidence) / 2,
                2,
            )
        logger.info(
            "llm_enhanced",
            node="detect_anomalies",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_anomalies",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "detect_anomalies",
        f"analyzing {len(state.log_patterns)} patterns",
        f"found {len(anomalies)} anomalies, max={max_score}",
        elapsed,
        "anomaly_engine",
    )
    await toolkit.record_metric(
        "anomalies",
        float(len(anomalies)),
    )

    return {
        "detected_anomalies": anomalies,
        "max_anomaly_score": max_score,
        "stage": LADStage.CORRELATE,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "detect_anomalies",
    }


async def correlate_events(
    state: LogAnomalyDetectorState,
) -> dict[str, Any]:
    """Correlate anomalies across sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    correlations = await toolkit.correlate_events(
        state.detected_anomalies,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "anomaly_count": len(state.detected_anomalies),
                "correlations": correlations[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CORRELATE,
            user_prompt=(f"Correlation context:\n{ctx}"),
            schema=CorrelationOutput,
        )
        if hasattr(llm_result, "correlations"):
            logger.info(
                "llm_enhanced",
                node="correlate_events",
                llm_correlations=len(
                    llm_result.correlations,
                ),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="correlate_events",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "correlate_events",
        f"correlating {len(state.detected_anomalies)} anomalies",
        f"found {len(correlations)} correlations",
        elapsed,
        "correlation_engine",
    )

    return {
        "correlated_events": correlations,
        "stage": LADStage.PRIORITIZE,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "correlate_events",
    }


async def prioritize_alerts(
    state: LogAnomalyDetectorState,
) -> dict[str, Any]:
    """Prioritize anomaly alerts."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    alerts = await toolkit.prioritize_alerts(
        state.detected_anomalies,
        state.correlated_events,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "anomaly_count": len(state.detected_anomalies),
                "correlation_count": len(
                    state.correlated_events,
                ),
                "alert_count": len(alerts),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_PRIORITIZE,
            user_prompt=(f"Prioritization context:\n{ctx}"),
            schema=PrioritizationOutput,
        )
        if hasattr(llm_result, "alerts"):
            logger.info(
                "llm_enhanced",
                node="prioritize_alerts",
                llm_alerts=len(llm_result.alerts),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="prioritize_alerts",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "prioritize_alerts",
        f"prioritizing {len(state.detected_anomalies)} anomalies",
        f"created {len(alerts)} alerts",
        elapsed,
        "alert_engine",
    )

    return {
        "prioritized_alerts": alerts,
        "stage": LADStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "prioritize_alerts",
    }


async def generate_report(
    state: LogAnomalyDetectorState,
) -> dict[str, Any]:
    """Generate final anomaly detection report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int(
            (datetime.now(UTC) - state.session_start).total_seconds() * 1000,
        )

    report = {
        "request_id": state.request_id,
        "total_records": state.total_records,
        "patterns": len(state.log_patterns),
        "new_patterns": state.new_pattern_count,
        "anomalies": len(state.detected_anomalies),
        "max_anomaly_score": state.max_anomaly_score,
        "correlations": len(state.correlated_events),
        "alerts": len(state.prioritized_alerts),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric(
        "scan_duration_ms",
        float(duration_ms),
    )
    await toolkit.record_metric(
        "total_anomalies",
        float(len(state.detected_anomalies)),
    )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "generate_report",
        f"finalizing detection {state.request_id}",
        f"report complete in {duration_ms}ms",
        elapsed,
        None,
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "complete",
    }
