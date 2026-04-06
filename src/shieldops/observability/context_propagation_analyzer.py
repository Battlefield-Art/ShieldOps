"""ContextPropagationAnalyzer — context propagation analyzer."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ContextPropagationAnalyzer = engine(
    "ContextPropagationAnalyzer",
    module="operations",  # uses record_item
    description="Context Propagation Analyzer.",
    enums={
        "propagation_type": EnumDef(
            "PropagationType",
            {
                "W3C_TRACE": "w3c_trace",
                "B3_HEADER": "b3_header",
                "JAEGER": "jaeger",
                "CUSTOM": "custom",
                "HYBRID": "hybrid",
            },
        ),
        "propagation_issue": EnumDef(
            "PropagationIssue",
            {
                "MISSING_CONTEXT": "missing_context",
                "BROKEN_CHAIN": "broken_chain",
                "DUPLICATE_ID": "duplicate_id",
                "INVALID_FORMAT": "invalid_format",
                "TIMEOUT": "timeout",
            },
        ),
        "coverage_level": EnumDef(
            "CoverageLevel",
            {
                "FULL": "full",
                "PARTIAL": "partial",
                "MINIMAL": "minimal",
                "NONE": "none",
                "UNKNOWN": "unknown",
            },
        ),
    },
)

# Backward-compatible re-exports
PropagationType = ContextPropagationAnalyzer.PropagationType
PropagationIssue = ContextPropagationAnalyzer.PropagationIssue
CoverageLevel = ContextPropagationAnalyzer.CoverageLevel
ContextPropagationAnalyzerRecord = ContextPropagationAnalyzer.Record
ContextPropagationAnalyzerAnalysis = ContextPropagationAnalyzer.Analysis
ContextPropagationAnalyzerReport = ContextPropagationAnalyzer.Report
