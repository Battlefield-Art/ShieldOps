"""Tool functions for Security Data Lake Agent."""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_data_lake.models import (
    DataAnalysis,
    DataQuery,
    DataSource,
    MergedResult,
    QueryExecution,
    QueryType,
    SourceIdentification,
)

logger = structlog.get_logger()


class SecurityDataLakeToolkit:
    """Tools for security data lake queries."""

    def __init__(
        self,
        db_client: Any | None = None,
        metrics_client: Any | None = None,
        search_client: Any | None = None,
    ) -> None:
        self._db = db_client
        self._metrics = metrics_client
        self._search = search_client

    async def parse_query(
        self,
        raw_text: str,
    ) -> DataQuery:
        """Parse a raw query text into structured form."""
        logger.info(
            "data_lake.parsing_query",
            query_len=len(raw_text),
        )

        # Basic keyword-based parsing
        q_type = QueryType.SEARCH
        lower = raw_text.lower()
        if "trend" in lower or "over time" in lower:
            q_type = QueryType.TREND
        elif "correlat" in lower:
            q_type = QueryType.CORRELATION
        elif "count" in lower or "how many" in lower or "aggregate" in lower:
            q_type = QueryType.AGGREGATE
        elif "export" in lower:
            q_type = QueryType.EXPORT

        hours = 24
        if "week" in lower:
            hours = 168
        elif "month" in lower:
            hours = 720
        elif "hour" in lower:
            hours = 1

        filters: dict[str, Any] = {}
        if "critical" in lower:
            filters["severity"] = "critical"
        if "high" in lower:
            filters["severity"] = "high"

        return DataQuery(
            id=f"dq-{uuid4().hex[:8]}",
            raw_text=raw_text,
            query_type=q_type,
            parsed_filters=filters,
            time_range_hours=hours,
        )

    async def identify_sources(
        self,
        query: DataQuery,
    ) -> SourceIdentification:
        """Identify relevant data sources."""
        logger.info(
            "data_lake.identifying_sources",
            query_type=query.query_type,
        )

        # Default: query most relevant sources
        sources = [
            DataSource.AGENT_FINDINGS,
            DataSource.AUDIT_LOGS,
        ]
        scores: dict[str, float] = {
            DataSource.AGENT_FINDINGS: 0.9,
            DataSource.AUDIT_LOGS: 0.8,
        }

        qt = query.query_type
        if qt == QueryType.AGGREGATE:
            sources.append(DataSource.AGENT_METRICS)
            scores[DataSource.AGENT_METRICS] = 0.85
        elif qt == QueryType.CORRELATION:
            sources.extend(
                [
                    DataSource.SCAN_RESULTS,
                    DataSource.REMEDIATION_RECORDS,
                ]
            )
            scores[DataSource.SCAN_RESULTS] = 0.75
            scores[DataSource.REMEDIATION_RECORDS] = 0.70

        return SourceIdentification(
            id=f"si-{uuid4().hex[:8]}",
            sources=sources,
            relevance_scores=scores,
            estimated_records=len(sources) * 50,
        )

    async def execute_query(
        self,
        query: DataQuery,
        source: DataSource,
    ) -> QueryExecution:
        """Execute a query on a single source."""
        logger.info(
            "data_lake.executing_query",
            source=source,
            query_type=query.query_type,
        )

        start = time.monotonic()

        # Stub records
        records: list[dict[str, Any]] = []
        count = 5
        for i in range(count):
            records.append(
                {
                    "id": f"rec-{uuid4().hex[:8]}",
                    "source": source.value,
                    "timestamp": time.time() - i * 3600,
                    "severity": ("critical" if i == 0 else "high" if i < 3 else "medium"),
                    "type": f"finding_{i}",
                    "details": (f"Record {i} from {source.value}"),
                }
            )

        elapsed = (time.monotonic() - start) * 1000

        return QueryExecution(
            id=f"qe-{uuid4().hex[:8]}",
            source=source,
            records_found=count,
            execution_time_ms=round(elapsed, 2),
            records=records,
        )

    async def merge_results(
        self,
        executions: list[QueryExecution],
    ) -> MergedResult:
        """Merge results from multiple sources."""
        logger.info(
            "data_lake.merging_results",
            source_count=len(executions),
        )

        all_records: list[dict[str, Any]] = []
        for ex in executions:
            all_records.extend(ex.records)

        # Sort by timestamp desc
        all_records.sort(
            key=lambda r: r.get("timestamp", 0),
            reverse=True,
        )

        # Simple dedup by id
        seen: set[str] = set()
        deduped: list[dict[str, Any]] = []
        for r in all_records:
            rid = r.get("id", "")
            if rid not in seen:
                seen.add(rid)
                deduped.append(r)

        return MergedResult(
            id=f"mr-{uuid4().hex[:8]}",
            total_records=len(deduped),
            sources_queried=len(executions),
            records=deduped,
            dedup_count=len(all_records) - len(deduped),
        )

    async def analyze_data(
        self,
        merged: MergedResult,
    ) -> DataAnalysis:
        """Perform basic analysis on merged data."""
        logger.info(
            "data_lake.analyzing_data",
            records=merged.total_records,
        )

        # Basic pattern detection
        severity_counts: dict[str, int] = {}
        source_counts: dict[str, int] = {}
        for r in merged.records:
            sev = r.get("severity", "unknown")
            src = r.get("source", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            source_counts[src] = source_counts.get(src, 0) + 1

        patterns = [
            f"Severity distribution: {severity_counts}",
            f"Source distribution: {source_counts}",
        ]

        return DataAnalysis(
            id=f"da-{uuid4().hex[:8]}",
            summary=(
                f"Analyzed {merged.total_records} records from {merged.sources_queried} sources"
            ),
            patterns=patterns,
            anomalies=[],
            correlations=[],
            insights=[],
        )
