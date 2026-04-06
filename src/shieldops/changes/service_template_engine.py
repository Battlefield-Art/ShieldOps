"""ServiceTemplateEngine Service template management, scaffolding automation, template version..."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ServiceTemplateEngine = engine(
    "ServiceTemplateEngine",
    module="operations",  # uses record_item
    description="Service template management with scaffolding automation.",
    enums={
        "template_type": EnumDef(
            "TemplateType",
            {
                "MICROSERVICE": "microservice",
                "LIBRARY": "library",
                "FRONTEND": "frontend",
                "DATA_PIPELINE": "data_pipeline",
                "INFRASTRUCTURE": "infrastructure",
            },
        ),
        "template_maturity": EnumDef(
            "TemplateMaturity",
            {
                "EXPERIMENTAL": "experimental",
                "BETA": "beta",
                "STABLE": "stable",
                "DEPRECATED": "deprecated",
                "ARCHIVED": "archived",
            },
        ),
        "scaffold_outcome": EnumDef(
            "ScaffoldOutcome",
            {
                "SUCCESS": "success",
                "PARTIAL": "partial",
                "FAILED": "failed",
                "SKIPPED": "skipped",
                "CUSTOM_OVERRIDE": "custom_override",
            },
        ),
    },
)

# Backward-compatible re-exports
TemplateType = ServiceTemplateEngine.TemplateType
TemplateMaturity = ServiceTemplateEngine.TemplateMaturity
ScaffoldOutcome = ServiceTemplateEngine.ScaffoldOutcome
ServiceTemplateRecord = ServiceTemplateEngine.Record
ServiceTemplateAnalysis = ServiceTemplateEngine.Analysis
ServiceTemplateReport = ServiceTemplateEngine.Report
