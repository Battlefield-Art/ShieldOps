"""Trace Completeness Verification Engine — verify trace completeness and integrity, detect mi..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TraceCompletenessVerificationEngine = engine(
    "TraceCompletenessVerificationEngine",
    description="Verify trace completeness and integrity, detect missing spans, rank traces...",
    enums={
        "completeness_type": EnumDef(
            "CompletenessType",
            {
                "FULL": "full",
                "PARTIAL": "partial",
                "FRAGMENTED": "fragmented",
                "ORPHANED": "orphaned",
            },
        ),
        "verification_method": EnumDef(
            "VerificationMethod",
            {
                "SPAN_COUNT": "span_count",
                "PARENT_CHECK": "parent_check",
                "DURATION_CHECK": "duration_check",
                "SEMANTIC": "semantic",
            },
        ),
        "integrity_status": EnumDef(
            "IntegrityStatus",
            {
                "VALID": "valid",
                "CORRUPTED": "corrupted",
                "INCOMPLETE": "incomplete",
                "SUSPICIOUS": "suspicious",
            },
        ),
    },
    record_fields=[
        FieldDef("service_name", str, ""),
        FieldDef("expected_spans", int, 0),
        FieldDef("actual_spans", int, 0),
        FieldDef("missing_spans", int, 0),
        FieldDef("orphaned_spans", int, 0),
        FieldDef("description", str, ""),
    ],
    score_field="completeness_score",
    key_field="trace_id",
)

# Backward-compatible re-exports
CompletenessType = TraceCompletenessVerificationEngine.CompletenessType
VerificationMethod = TraceCompletenessVerificationEngine.VerificationMethod
IntegrityStatus = TraceCompletenessVerificationEngine.IntegrityStatus
TraceCompletenessRecord = TraceCompletenessVerificationEngine.Record
TraceCompletenessAnalysis = TraceCompletenessVerificationEngine.Analysis
TraceCompletenessReport = TraceCompletenessVerificationEngine.Report
