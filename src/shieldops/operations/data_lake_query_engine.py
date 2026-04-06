"""Data Lake Query Engine — parse, execute, and cache queries."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

DataLakeQueryEngine = engine(
    "DataLakeQueryEngine",
    module="operations",  # uses record_item
    description="Parse, execute, and cache data lake queries.",
    enums={
        "language": EnumDef(
            "QueryLanguage",
            {
                "SQL": "sql",
                "KQL": "kql",
                "SPL": "spl",
                "LUCENE": "lucene",
                "CUSTOM": "custom",
            },
        ),
        "index_type": EnumDef(
            "IndexType",
            {
                "TIME_SERIES": "time_series",
                "FULL_TEXT": "full_text",
                "COLUMNAR": "columnar",
                "GRAPH": "graph",
            },
        ),
        "cache": EnumDef(
            "CacheStrategy",
            {
                "NONE": "none",
                "LRU": "lru",
                "TTL": "ttl",
                "WRITE_THROUGH": "write_through",
            },
        ),
    },
    key_field="query_name",
)

# Backward-compatible re-exports
QueryLanguage = DataLakeQueryEngine.QueryLanguage
IndexType = DataLakeQueryEngine.IndexType
CacheStrategy = DataLakeQueryEngine.CacheStrategy
QueryRecord = DataLakeQueryEngine.Record
QueryAnalysis = DataLakeQueryEngine.Analysis
QueryReport = DataLakeQueryEngine.Report
