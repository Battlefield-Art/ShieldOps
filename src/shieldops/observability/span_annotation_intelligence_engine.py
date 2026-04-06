"""Span Annotation Intelligence Engine — evaluate span annotation coverage, detect missing ann..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

SpanAnnotationIntelligenceEngine = engine(
    "SpanAnnotationIntelligenceEngine",
    description="Evaluate span annotation coverage, detect missing annotations, optimize ann...",
    enums={
        "annotation_type": EnumDef(
            "AnnotationType",
            {
                "ERROR": "error",
                "WARNING": "warning",
                "INFO": "info",
                "CUSTOM": "custom",
            },
        ),
        "annotation_source": EnumDef(
            "AnnotationSource",
            {
                "AUTOMATIC": "automatic",
                "MANUAL": "manual",
                "ML_INFERRED": "ml_inferred",
                "POLICY": "policy",
            },
        ),
        "annotation_quality": EnumDef(
            "AnnotationQuality",
            {
                "ACCURATE": "accurate",
                "APPROXIMATE": "approximate",
                "STALE": "stale",
                "INCORRECT": "incorrect",
            },
        ),
    },
    record_fields=[
        FieldDef("trace_id", str, ""),
        FieldDef("service_name", str, ""),
        FieldDef("missing_annotations", int, 0),
        FieldDef("total_spans", int, 0),
        FieldDef("annotated_spans", int, 0),
        FieldDef("description", str, ""),
    ],
    score_field="coverage_score",
    key_field="span_id",
)

# Backward-compatible re-exports
AnnotationType = SpanAnnotationIntelligenceEngine.AnnotationType
AnnotationSource = SpanAnnotationIntelligenceEngine.AnnotationSource
AnnotationQuality = SpanAnnotationIntelligenceEngine.AnnotationQuality
SpanAnnotationRecord = SpanAnnotationIntelligenceEngine.Record
SpanAnnotationAnalysis = SpanAnnotationIntelligenceEngine.Analysis
SpanAnnotationReport = SpanAnnotationIntelligenceEngine.Report
