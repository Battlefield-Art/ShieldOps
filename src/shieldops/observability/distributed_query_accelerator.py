"""DistributedQueryAccelerator — query acceleration."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

DistributedQueryAccelerator = engine(
    "DistributedQueryAccelerator",
    description="Distributed Query Accelerator. Analyzes and optimizes distributed query pat...",
    enums={
        "complexity": EnumDef(
            "QueryComplexity",
            {
                "SIMPLE": "simple",
                "MODERATE": "moderate",
                "COMPLEX": "complex",
                "EXTREME": "extreme",
            },
        ),
        "cache_strategy": EnumDef(
            "CacheStrategy",
            {
                "LRU": "lru",
                "LFU": "lfu",
                "ADAPTIVE": "adaptive",
                "NONE": "none",
            },
        ),
        "data_locality": EnumDef(
            "DataLocality",
            {
                "LOCAL": "local",
                "REGIONAL": "regional",
                "GLOBAL": "global",
            },
        ),
    },
    record_fields=[
        FieldDef("query_time_ms", float, 0.0),
        FieldDef("cache_hit_rate", float, 0.0),
    ],
)

# Backward-compatible re-exports
QueryComplexity = DistributedQueryAccelerator.QueryComplexity
CacheStrategy = DistributedQueryAccelerator.CacheStrategy
DataLocality = DistributedQueryAccelerator.DataLocality
QueryRecord = DistributedQueryAccelerator.Record
QueryAnalysis = DistributedQueryAccelerator.Analysis
QueryReport = DistributedQueryAccelerator.Report
