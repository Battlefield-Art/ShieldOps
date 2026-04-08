"""Node implementations for Security Data Lake Agent."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.security_data_lake.models import (
    DataLakeStage,
    DataSource,
    QueryType,
    SecurityDataLakeState,
)
from shieldops.agents.security_data_lake.prompts import (
    SYSTEM_DATA_ANALYSIS,
    SYSTEM_DATA_LAKE_REPORT,
    SYSTEM_QUERY_PARSE,
    SYSTEM_SOURCE_SELECTION,
    DataAnalysisOutput,
    DataLakeReportOutput,
    QueryParseOutput,
    SourceSelectionOutput,
)
from shieldops.agents.security_data_lake.tools import (
    SecurityDataLakeToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityDataLakeToolkit | None = None


def _get_toolkit() -> SecurityDataLakeToolkit:
    if _toolkit is None:
        return SecurityDataLakeToolkit()
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


# -------------------------------------------------------
# Node 1: parse_query
# -------------------------------------------------------
async def parse_query(
    state: SecurityDataLakeState,
) -> dict[str, Any]:
    """Parse natural language query."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "data_lake.parse_query",
        tenant_id=state.tenant_id,
    )

    query = await toolkit.parse_query(state.query.raw_text)

    # LLM-powered NL parsing
    try:
        result = cast(
            QueryParseOutput,
            await llm_structured(
                system_prompt=SYSTEM_QUERY_PARSE,
                user_prompt=state.query.raw_text,
                schema=QueryParseOutput,
            ),
        )
        if result.query_type in [q.value for q in QueryType]:
            query.query_type = QueryType(result.query_type)
        query.parsed_filters = result.filters
        query.time_range_hours = result.time_range_hours
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="parse_query",
            error=str(exc),
        )

    chain_entry = f"Parsed query: type={query.query_type.value} range={query.time_range_hours}h"

    return {
        "query": query,
        "stage": DataLakeStage.IDENTIFY_SOURCES,
        "reasoning_chain": [chain_entry],
        "current_step": "parse_query",
        "session_start": start,
    }


# -------------------------------------------------------
# Node 2: identify_sources
# -------------------------------------------------------
async def identify_sources(
    state: SecurityDataLakeState,
) -> dict[str, Any]:
    """Identify relevant data sources."""
    toolkit = _get_toolkit()

    logger.info(
        "data_lake.identify_sources",
        query_type=state.query.query_type,
    )

    sources = await toolkit.identify_sources(state.query)

    # LLM enrichment
    user_prompt = (
        f"Query: {state.query.raw_text}\n"
        f"Type: {state.query.query_type.value}\n"
        f"Filters: {state.query.parsed_filters}"
    )
    try:
        result = cast(
            SourceSelectionOutput,
            await llm_structured(
                system_prompt=(SYSTEM_SOURCE_SELECTION),
                user_prompt=user_prompt,
                schema=SourceSelectionOutput,
            ),
        )
        valid = [DataSource(s) for s in result.sources if s in [d.value for d in DataSource]]
        if valid:
            sources.sources = valid
            sources.relevance_scores = result.relevance_scores
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="identify_sources",
            error=str(exc),
        )

    chain_entry = (
        f"Sources: {len(sources.sources)} identified"
        f" ({', '.join(s.value for s in sources.sources)})"
    )

    return {
        "sources_identified": sources,
        "stage": DataLakeStage.EXECUTE_QUERIES,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "identify_sources",
    }


# -------------------------------------------------------
# Node 3: execute_queries
# -------------------------------------------------------
async def execute_queries(
    state: SecurityDataLakeState,
) -> dict[str, Any]:
    """Execute queries on all identified sources."""
    toolkit = _get_toolkit()

    logger.info(
        "data_lake.execute_queries",
        sources=len(state.sources_identified.sources),
    )

    results = []
    for source in state.sources_identified.sources:
        result = await toolkit.execute_query(state.query, source)
        results.append(result)

    total = sum(r.records_found for r in results)
    chain_entry = f"Queries: {len(results)} executed, {total} records found"

    return {
        "query_results": results,
        "sources_queried": len(results),
        "stage": DataLakeStage.MERGE_RESULTS,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "execute_queries",
    }


# -------------------------------------------------------
# Node 4: merge_results
# -------------------------------------------------------
async def merge_results(
    state: SecurityDataLakeState,
) -> dict[str, Any]:
    """Merge results from all sources."""
    toolkit = _get_toolkit()

    logger.info(
        "data_lake.merge_results",
        result_count=len(state.query_results),
    )

    merged = await toolkit.merge_results(state.query_results)

    chain_entry = f"Merged: {merged.total_records} records, {merged.dedup_count} duplicates removed"

    return {
        "merged_data": merged,
        "records_returned": merged.total_records,
        "stage": DataLakeStage.ANALYZE_DATA,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "merge_results",
    }


# -------------------------------------------------------
# Node 5: analyze_data
# -------------------------------------------------------
async def analyze_data(
    state: SecurityDataLakeState,
) -> dict[str, Any]:
    """Analyze merged data with LLM."""
    toolkit = _get_toolkit()

    logger.info(
        "data_lake.analyze_data",
        records=state.merged_data.total_records,
    )

    analysis = await toolkit.analyze_data(state.merged_data)

    # LLM deep analysis
    lines = [
        f"## Query: {state.query.raw_text}",
        f"## Records: {state.merged_data.total_records}",
        "## Sample Data",
    ]
    for r in state.merged_data.records[:10]:
        lines.append(f"- {r.get('source')}: {r.get('severity')} — {r.get('details', '')[:80]}")
    user_prompt = "\n".join(lines)

    try:
        result = cast(
            DataAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_DATA_ANALYSIS,
                user_prompt=user_prompt,
                schema=DataAnalysisOutput,
            ),
        )
        analysis.summary = result.summary[:300]
        analysis.patterns = result.patterns[:5]
        analysis.anomalies = result.anomalies[:5]
        analysis.correlations = result.correlations[:5]
        analysis.insights = result.insights[:5]
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="analyze_data",
            error=str(exc),
        )

    chain_entry = (
        f"Analysis: {len(analysis.patterns)} "
        f"patterns, "
        f"{len(analysis.anomalies)} anomalies, "
        f"{len(analysis.insights)} insights"
    )

    return {
        "analysis": analysis,
        "stage": DataLakeStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "analyze_data",
    }


# -------------------------------------------------------
# Node 6: report
# -------------------------------------------------------
async def report(
    state: SecurityDataLakeState,
) -> dict[str, Any]:
    """Generate final data lake report."""
    logger.info(
        "data_lake.report",
        records=state.records_returned,
        sources=state.sources_queried,
    )

    lines = [
        "## Data Lake Query Report",
        f"- Query: {state.query.raw_text}",
        f"- Records: {state.records_returned}",
        f"- Sources: {state.sources_queried}",
        f"- Summary: {state.analysis.summary}",
    ]
    for entry in state.reasoning_chain:
        lines.append(f"- {entry}")
    user_prompt = "\n".join(lines)

    try:
        result = cast(
            DataLakeReportOutput,
            await llm_structured(
                system_prompt=(SYSTEM_DATA_LAKE_REPORT),
                user_prompt=user_prompt,
                schema=DataLakeReportOutput,
            ),
        )
        summary = result.executive_summary
        findings = result.key_findings
    except Exception as exc:
        logger.debug(
            "llm_fallback",
            node="report",
            error=str(exc),
        )
        summary = (
            f"Query returned {state.records_returned} records from {state.sources_queried} sources"
        )
        findings = state.analysis.patterns[:5]

    duration = 0
    if state.session_start:
        duration = _elapsed_ms(state.session_start)

    stats = {
        "query": state.query.raw_text,
        "query_type": state.query.query_type,
        "records_returned": state.records_returned,
        "sources_queried": state.sources_queried,
        "patterns": len(state.analysis.patterns),
        "anomalies": len(state.analysis.anomalies),
        "summary": summary[:500],
        "key_findings": findings[:5],
    }

    chain_entry = f"Report: {state.records_returned} records from {state.sources_queried} sources"

    return {
        "stats": stats,
        "stage": DataLakeStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, chain_entry],
        "current_step": "complete",
        "session_duration_ms": duration,
    }
