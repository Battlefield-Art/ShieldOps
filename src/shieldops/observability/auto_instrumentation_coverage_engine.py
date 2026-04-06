"""Auto Instrumentation Coverage Engine — compute instrumentation coverage, detect propagation..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AutoInstrumentationCoverageEngine = engine(
    "AutoInstrumentationCoverageEngine",
    description="Compute instrumentation coverage, detect propagation breaks, prioritize ins...",
    enums={
        "language": EnumDef(
            "InstrumentationLanguage",
            {
                "PYTHON": "python",
                "JAVA": "java",
                "NODE": "node",
                "GO": "go",
            },
        ),
        "coverage_status": EnumDef(
            "CoverageStatus",
            {
                "FULLY_INSTRUMENTED": "fully_instrumented",
                "PARTIALLY_INSTRUMENTED": "partially_instrumented",
                "UNINSTRUMENTED": "uninstrumented",
                "MISCONFIGURED": "misconfigured",
            },
        ),
        "instrumentation_quality": EnumDef(
            "InstrumentationQuality",
            {
                "RICH_CONTEXT": "rich_context",
                "BASIC_SPANS": "basic_spans",
                "MISSING_ATTRIBUTES": "missing_attributes",
                "BROKEN_PROPAGATION": "broken_propagation",
            },
        ),
    },
    record_fields=[
        FieldDef("endpoint_count", int, 0),
        FieldDef("instrumented_endpoints", int, 0),
        FieldDef("propagation_breaks", int, 0),
        FieldDef("missing_attribute_count", int, 0),
        FieldDef("description", str, ""),
    ],
    key_field="service_name",
)

# Backward-compatible re-exports
InstrumentationLanguage = AutoInstrumentationCoverageEngine.InstrumentationLanguage
CoverageStatus = AutoInstrumentationCoverageEngine.CoverageStatus
InstrumentationQuality = AutoInstrumentationCoverageEngine.InstrumentationQuality
AutoInstrumentationRecord = AutoInstrumentationCoverageEngine.Record
AutoInstrumentationAnalysis = AutoInstrumentationCoverageEngine.Analysis
AutoInstrumentationReport = AutoInstrumentationCoverageEngine.Report
