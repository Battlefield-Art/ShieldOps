"""AutoInstrumentationEngine — track auto-instrumentation coverage across services."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AutoInstrumentationEngine = engine(
    "AutoInstrumentationEngine",
    description="Track auto-instrumentation coverage — which services have OTel instrumentat...",
    enums={
        "language": EnumDef(
            "InstrumentationLanguage",
            {
                "PYTHON": "python",
                "JAVA": "java",
                "NODEJS": "nodejs",
                "GO": "go",
                "DOTNET": "dotnet",
            },
        ),
        "method": EnumDef(
            "InstrumentationMethod",
            {
                "RUNTIME_PATCH": "runtime_patch",
                "SDK_MANUAL": "sdk_manual",
                "EBPF": "ebpf",
                "OPERATOR_INJECTION": "operator_injection",
            },
        ),
        "coverage_status": EnumDef(
            "CoverageStatus",
            {
                "FULL": "full",
                "PARTIAL": "partial",
                "NONE": "none",
                "INCOMPATIBLE": "incompatible",
            },
        ),
    },
    record_fields=[
        FieldDef("libraries_instrumented", int, 0),
        FieldDef("libraries_total", int, 0),
        FieldDef("trace_coverage_pct", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="service_name",
)

# Backward-compatible re-exports
InstrumentationLanguage = AutoInstrumentationEngine.InstrumentationLanguage
InstrumentationMethod = AutoInstrumentationEngine.InstrumentationMethod
CoverageStatus = AutoInstrumentationEngine.CoverageStatus
AutoInstrumentationRecord = AutoInstrumentationEngine.Record
AutoInstrumentationAnalysis = AutoInstrumentationEngine.Analysis
AutoInstrumentationReport = AutoInstrumentationEngine.Report
