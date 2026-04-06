"""Trace Root Cause Analyzer Engine — analyze root causes from trace data, correlate cause pat..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TraceRootCauseAnalyzerEngine = engine(
    "TraceRootCauseAnalyzerEngine",
    description="Analyze root causes from trace data, correlate cause patterns, rank causes...",
    enums={
        "root_cause_type": EnumDef(
            "RootCauseType",
            {
                "SERVICE_ERROR": "service_error",
                "NETWORK_ISSUE": "network_issue",
                "RESOURCE_LIMIT": "resource_limit",
                "CONFIGURATION": "configuration",
            },
        ),
        "analysis_depth": EnumDef(
            "AnalysisDepth",
            {
                "SHALLOW": "shallow",
                "MODERATE": "moderate",
                "DEEP": "deep",
                "EXHAUSTIVE": "exhaustive",
            },
        ),
        "cause_confidence": EnumDef(
            "CauseConfidence",
            {
                "CONFIRMED": "confirmed",
                "PROBABLE": "probable",
                "POSSIBLE": "possible",
                "SPECULATIVE": "speculative",
            },
        ),
    },
    record_fields=[
        FieldDef("service_name", str, ""),
        FieldDef("affected_spans", int, 0),
        FieldDef("error_message", str, ""),
        FieldDef("description", str, ""),
    ],
    score_field="likelihood_score",
    key_field="trace_id",
)

# Backward-compatible re-exports
RootCauseType = TraceRootCauseAnalyzerEngine.RootCauseType
AnalysisDepth = TraceRootCauseAnalyzerEngine.AnalysisDepth
CauseConfidence = TraceRootCauseAnalyzerEngine.CauseConfidence
TraceRootCauseRecord = TraceRootCauseAnalyzerEngine.Record
TraceRootCauseAnalysis = TraceRootCauseAnalyzerEngine.Analysis
TraceRootCauseReport = TraceRootCauseAnalyzerEngine.Report
