"""Node implementations for the Log Intelligence Agent LangGraph workflow."""

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.log_intelligence.models import (
    LogBatch,
    LogInsight,
    LogIntelligenceState,
    LogSource,
    LogStage,
    NormalizedLog,
    PatternDetection,
    ReasoningStep,
    ThreatCorrelation,
)
from shieldops.agents.log_intelligence.prompts import (
    SYSTEM_INSIGHT_GENERATION,
    SYSTEM_PATTERN_ANALYSIS,
    SYSTEM_REPORT,
    SYSTEM_THREAT_CORRELATION,
    InsightOutput,
    PatternAnalysisOutput,
    ReportOutput,
    ThreatCorrelationOutput,
)
from shieldops.agents.log_intelligence.tools import (
    LogIntelligenceToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: LogIntelligenceToolkit | None = None


def set_toolkit(toolkit: LogIntelligenceToolkit) -> None:
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> LogIntelligenceToolkit:
    if _toolkit is None:
        return LogIntelligenceToolkit()
    return _toolkit


_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


async def ingest_logs(
    state: LogIntelligenceState,
) -> dict[str, Any]:
    """Ingest logs from configured multi-source backends."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    sources = [s.value for s in state.sources] if state.sources else [LogSource.CUSTOM.value]
    result = await toolkit.ingest_logs(
        tenant_id=state.tenant_id,
        sources=sources,
        time_range_hours=state.time_range_hours,
        query=state.query,
    )

    raw_batches = result.get("batches", [])
    batches = [LogBatch(**b) for b in raw_batches if isinstance(b, dict)]
    total = result.get("total_ingested", 0)
    query_ms = result.get("query_ms", 0)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="ingest_logs",
        input_summary=(f"Ingesting from {len(sources)} sources, {state.time_range_hours}h window"),
        output_summary=(f"Ingested {total} logs in {len(batches)} batches"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="multi_source_ingestion",
    )

    await toolkit.record_metric("logs_ingested", float(total))

    return {
        "batches": batches,
        "logs_ingested": total,
        "query_performance_ms": query_ms,
        "stage": LogStage.PARSE_AND_NORMALIZE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "ingest_logs",
        "session_start": start,
    }


async def parse_and_normalize(
    state: LogIntelligenceState,
) -> dict[str, Any]:
    """Parse and normalize logs from heterogeneous formats."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    batch_dicts = [b.model_dump() for b in state.batches]
    result = await toolkit.normalize_logs(batch_dicts)

    raw_normalized = result.get("normalized", [])
    normalized = [NormalizedLog(**n) for n in raw_normalized if isinstance(n, dict)]
    errors = result.get("errors", 0)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="parse_and_normalize",
        input_summary=(f"Normalizing {len(state.batches)} batches"),
        output_summary=(f"Normalized {len(normalized)} logs, {errors} errors"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="normalizer",
    )

    return {
        "normalized_logs": normalized,
        "normalization_errors": errors,
        "stage": LogStage.DETECT_PATTERNS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "parse_and_normalize",
    }


async def detect_patterns(
    state: LogIntelligenceState,
) -> dict[str, Any]:
    """Detect patterns using statistical + LLM analysis."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    log_dicts = [n.model_dump() for n in state.normalized_logs]
    raw_patterns = await toolkit.detect_patterns(
        normalized_logs=log_dicts,
        time_range_hours=state.time_range_hours,
    )
    patterns = [PatternDetection(**p) for p in raw_patterns if isinstance(p, dict)]

    # LLM enhancement: deeper pattern classification
    try:
        context = _json.dumps(
            {
                "tenant_id": state.tenant_id,
                "sources": [s.value for s in state.sources],
                "log_count": len(state.normalized_logs),
                "raw_pattern_count": len(patterns),
                "sample_logs": log_dicts[:15],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_PATTERN_ANALYSIS,
            user_prompt=(f"Log pattern context:\n{context}"),
            schema=PatternAnalysisOutput,
        )
        if hasattr(llm_result, "pattern_type") and llm_result.pattern_type and not patterns:
            patterns.append(
                PatternDetection(
                    id="llm-pat-001",
                    pattern_type=llm_result.pattern_type,
                    description=getattr(llm_result, "description", ""),
                    severity=getattr(llm_result, "severity", "medium"),
                    confidence=getattr(llm_result, "confidence", 0.5),
                )
            )
        logger.info("llm_enhanced", node="detect_patterns")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_patterns",
        )

    # Determine max severity
    max_sev = "info"
    for p in patterns:
        rank = _SEVERITY_RANK.get(p.severity, 0)
        if rank > _SEVERITY_RANK.get(max_sev, 0):
            max_sev = p.severity

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="detect_patterns",
        input_summary=(f"Analyzing {len(state.normalized_logs)} normalized logs"),
        output_summary=(f"Detected {len(patterns)} patterns, max severity={max_sev}"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="pattern_detector",
    )

    return {
        "patterns_detected": patterns,
        "max_severity": max_sev,
        "stage": LogStage.CORRELATE_THREATS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_patterns",
    }


async def correlate_threats(
    state: LogIntelligenceState,
) -> dict[str, Any]:
    """Correlate patterns to threats using intel + LLM."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    pattern_dicts = [p.model_dump() for p in state.patterns_detected]
    raw_threats = await toolkit.correlate_threats(
        patterns=pattern_dicts,
        tenant_id=state.tenant_id,
    )
    threats = [ThreatCorrelation(**t) for t in raw_threats if isinstance(t, dict)]

    # LLM enhancement: deeper threat correlation
    try:
        context = _json.dumps(
            {
                "tenant_id": state.tenant_id,
                "patterns": pattern_dicts[:15],
                "max_severity": state.max_severity,
                "sources": [s.value for s in state.sources],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_THREAT_CORRELATION,
            user_prompt=(f"Threat correlation context:\n{context}"),
            schema=ThreatCorrelationOutput,
        )
        if hasattr(llm_result, "threat_category") and llm_result.threat_category and not threats:
            threats.append(
                ThreatCorrelation(
                    id="llm-threat-001",
                    pattern_ids=[p.id for p in state.patterns_detected[:5]],
                    threat_category=(llm_result.threat_category),
                    mitre_technique=getattr(
                        llm_result,
                        "mitre_technique",
                        "",
                    ),
                    description=getattr(llm_result, "description", ""),
                    severity=getattr(llm_result, "severity", "medium"),
                    confidence=getattr(llm_result, "confidence", 0.5),
                    ioc_matches=getattr(
                        llm_result,
                        "ioc_indicators",
                        [],
                    ),
                    recommended_action=getattr(
                        llm_result,
                        "recommended_action",
                        "",
                    ),
                )
            )
        logger.info("llm_enhanced", node="correlate_threats")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="correlate_threats",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="correlate_threats",
        input_summary=(f"Correlating {len(state.patterns_detected)} patterns against threat intel"),
        output_summary=(f"Found {len(threats)} threat correlations"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="threat_correlator",
    )

    return {
        "threats_correlated": threats,
        "stage": LogStage.GENERATE_INSIGHTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "correlate_threats",
    }


async def generate_insights(
    state: LogIntelligenceState,
) -> dict[str, Any]:
    """Generate actionable insights via toolkit + LLM."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    pattern_dicts = [p.model_dump() for p in state.patterns_detected]
    threat_dicts = [t.model_dump() for t in state.threats_correlated]
    raw_insights = await toolkit.generate_insights(
        patterns=pattern_dicts,
        threats=threat_dicts,
    )
    insights = [LogInsight(**i) for i in raw_insights if isinstance(i, dict)]

    # LLM enhancement: synthesize insights
    try:
        context = _json.dumps(
            {
                "tenant_id": state.tenant_id,
                "patterns": pattern_dicts[:10],
                "threats": threat_dicts[:10],
                "max_severity": state.max_severity,
                "logs_ingested": state.logs_ingested,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_INSIGHT_GENERATION,
            user_prompt=(f"Insight generation context:\n{context}"),
            schema=InsightOutput,
        )
        if hasattr(llm_result, "title") and llm_result.title:
            insights.append(
                LogInsight(
                    id="llm-insight-001",
                    title=llm_result.title,
                    description=getattr(llm_result, "description", ""),
                    insight_type=getattr(
                        llm_result,
                        "insight_type",
                        "security",
                    ),
                    priority=getattr(llm_result, "priority", "medium"),
                    recommendation=getattr(
                        llm_result,
                        "recommendation",
                        "",
                    ),
                )
            )
        logger.info("llm_enhanced", node="generate_insights")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_insights",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_insights",
        input_summary=(
            f"Synthesizing {len(state.patterns_detected)}"
            f" patterns + "
            f"{len(state.threats_correlated)} threats"
        ),
        output_summary=(f"Generated {len(insights)} insights"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="insight_generator",
    )

    return {
        "insights_generated": insights,
        "stage": LogStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "generate_insights",
    }


async def generate_report(
    state: LogIntelligenceState,
) -> dict[str, Any]:
    """Generate a final log intelligence report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    parts = [
        (f"Log Intelligence Report -- Tenant {state.tenant_id}"),
        f"Time range: {state.time_range_hours}h",
        f"Sources: {len(state.sources)}",
        f"Logs ingested: {state.logs_ingested}",
        (f"Patterns detected: {len(state.patterns_detected)}"),
        (f"Threats correlated: {len(state.threats_correlated)}"),
        (f"Insights generated: {len(state.insights_generated)}"),
        f"Max severity: {state.max_severity}",
    ]
    summary = ". ".join(parts)

    # LLM enhancement: executive summary
    try:
        context = _json.dumps(
            {
                "tenant_id": state.tenant_id,
                "logs_ingested": state.logs_ingested,
                "pattern_count": len(state.patterns_detected),
                "threats": [t.model_dump() for t in state.threats_correlated[:10]],
                "insights": [i.model_dump() for i in state.insights_generated[:10]],
                "max_severity": state.max_severity,
                "sources": [s.value for s in state.sources],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Full analysis context:\n{context}"),
            schema=ReportOutput,
        )
        if hasattr(llm_result, "summary") and llm_result.summary:
            summary = llm_result.summary
        logger.info("llm_enhanced", node="generate_report")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    await toolkit.record_metric("analysis_duration_ms", float(duration_ms))

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary="Compiling final intelligence report",
        output_summary=(f"Report generated ({len(summary)} chars), duration={duration_ms}ms"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )

    return {
        "report_summary": summary,
        "session_duration_ms": duration_ms,
        "stage": LogStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
