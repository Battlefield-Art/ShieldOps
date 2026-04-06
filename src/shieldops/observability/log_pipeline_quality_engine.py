"""LogPipelineQualityEngine — Track log pipeline quality metrics."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

LogPipelineQualityEngine = engine(
    "LogPipelineQualityEngine",
    description="Track log pipeline quality (parsing success, format consistency, enrichment).",
    enums={
        "dimension": EnumDef(
            "LogQualityDimension",
            {
                "PARSE_RATE": "parse_rate",
                "FORMAT_CONSISTENCY": "format_consistency",
                "ENRICHMENT_COVERAGE": "enrichment_coverage",
            },
        ),
        "grade": EnumDef(
            "QualityGrade",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "FAIR": "fair",
                "POOR": "poor",
            },
        ),
        "issue": EnumDef(
            "PipelineIssue",
            {
                "PARSE_FAILURE": "parse_failure",
                "MISSING_FIELDS": "missing_fields",
                "FORMAT_MISMATCH": "format_mismatch",
            },
        ),
    },
    record_fields=[
        FieldDef("record_count", int, 0),
        FieldDef("failure_rate", float, 0.0),
    ],
)

# Backward-compatible re-exports
LogQualityDimension = LogPipelineQualityEngine.LogQualityDimension
QualityGrade = LogPipelineQualityEngine.QualityGrade
PipelineIssue = LogPipelineQualityEngine.PipelineIssue
LogPipelineQualityRecord = LogPipelineQualityEngine.Record
LogPipelineQualityAnalysis = LogPipelineQualityEngine.Analysis
LogPipelineQualityReport = LogPipelineQualityEngine.Report
