"""OtelExtensionManagerEngine — Manage OTel Collector extensions."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

OtelExtensionManagerEngine = engine(
    "OtelExtensionManagerEngine",
    description="Manage OTel Collector extensions (health_check, pprof, zpages, auth).",
    enums={
        "extension_type": EnumDef(
            "ExtensionType",
            {
                "HEALTH_CHECK": "health_check",
                "PPROF": "pprof",
                "ZPAGES": "zpages",
                "BEARERTOKENAUTH": "bearertokenauth",
                "OAUTH2CLIENT": "oauth2client",
            },
        ),
        "extension_status": EnumDef(
            "ExtensionStatus",
            {
                "ENABLED": "enabled",
                "DISABLED": "disabled",
                "ERROR": "error",
            },
        ),
        "extension_priority": EnumDef(
            "ExtensionPriority",
            {
                "REQUIRED": "required",
                "RECOMMENDED": "recommended",
                "OPTIONAL": "optional",
            },
        ),
    },
    record_fields=[
        FieldDef("config_valid", bool, True),
        FieldDef("port", int, 0),
    ],
)

# Backward-compatible re-exports
ExtensionType = OtelExtensionManagerEngine.ExtensionType
ExtensionStatus = OtelExtensionManagerEngine.ExtensionStatus
ExtensionPriority = OtelExtensionManagerEngine.ExtensionPriority
OtelExtensionManagerRecord = OtelExtensionManagerEngine.Record
OtelExtensionManagerAnalysis = OtelExtensionManagerEngine.Analysis
OtelExtensionManagerReport = OtelExtensionManagerEngine.Report
