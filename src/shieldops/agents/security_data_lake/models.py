"""State models for Security Data Lake Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DataLakeStage(StrEnum):
    """Stages of the data lake query workflow."""

    PARSE_QUERY = "parse_query"
    IDENTIFY_SOURCES = "identify_sources"
    EXECUTE_QUERIES = "execute_queries"
    MERGE_RESULTS = "merge_results"
    ANALYZE_DATA = "analyze_data"
    REPORT = "report"


class DataSource(StrEnum):
    """Available data sources in the lake."""

    AGENT_FINDINGS = "agent_findings"
    AGENT_METRICS = "agent_metrics"
    AUDIT_LOGS = "audit_logs"
    SCAN_RESULTS = "scan_results"
    REMEDIATION_RECORDS = "remediation_records"
    TICKET_DATA = "ticket_data"


class QueryType(StrEnum):
    """Types of queries supported."""

    SEARCH = "search"
    AGGREGATE = "aggregate"
    TREND = "trend"
    CORRELATION = "correlation"
    EXPORT = "export"


class DataQuery(BaseModel):
    """Parsed data lake query."""

    id: str = ""
    raw_text: str = ""
    query_type: QueryType = QueryType.SEARCH
    parsed_filters: dict[str, Any] = Field(default_factory=dict)
    time_range_hours: int = 24
    limit: int = 100
    sort_by: str = "timestamp"
    sort_order: str = "desc"


class SourceIdentification(BaseModel):
    """Identification of relevant data sources."""

    id: str = ""
    sources: list[DataSource] = Field(default_factory=list)
    relevance_scores: dict[str, float] = Field(default_factory=dict)
    estimated_records: int = 0


class QueryExecution(BaseModel):
    """Result of executing a query on one source."""

    id: str = ""
    source: DataSource = DataSource.AGENT_FINDINGS
    records_found: int = 0
    execution_time_ms: float = 0.0
    records: list[dict[str, Any]] = Field(default_factory=list)
    error: str = ""


class MergedResult(BaseModel):
    """Merged results from multiple sources."""

    id: str = ""
    total_records: int = 0
    sources_queried: int = 0
    records: list[dict[str, Any]] = Field(default_factory=list)
    dedup_count: int = 0


class DataAnalysis(BaseModel):
    """Analysis of merged data."""

    id: str = ""
    summary: str = ""
    patterns: list[str] = Field(default_factory=list)
    anomalies: list[str] = Field(default_factory=list)
    correlations: list[str] = Field(default_factory=list)
    insights: list[str] = Field(default_factory=list)


class SecurityDataLakeState(BaseModel):
    """Full state of a data lake query."""

    # Identity
    request_id: str = ""
    stage: DataLakeStage = DataLakeStage.PARSE_QUERY
    tenant_id: str = ""

    # Data
    query: DataQuery = Field(default_factory=DataQuery)
    sources_identified: SourceIdentification = Field(default_factory=SourceIdentification)
    query_results: list[QueryExecution] = Field(default_factory=list)
    merged_data: MergedResult = Field(default_factory=MergedResult)
    analysis: DataAnalysis = Field(default_factory=DataAnalysis)

    # Metrics
    records_returned: int = 0
    sources_queried: int = 0
    stats: dict[str, Any] = Field(default_factory=dict)

    # Tracking
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = "init"
    session_start: datetime | None = None
    session_duration_ms: int = 0
    error: str = ""
