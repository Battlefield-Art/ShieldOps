"""AI Supply Chain Integrity — verify AI component provenance."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AISupplyChainIntegrityEngine = engine(
    "AISupplyChainIntegrityEngine",
    description="Verify AI component supply chain integrity.",
    enums={
        "component_type": EnumDef(
            "ComponentType",
            {
                "MODEL_WEIGHT": "model_weight",
                "RAG_DOC": "rag_doc",
                "PROMPT_TEMPLATE": "prompt_template",
                "TOOL_DEF": "tool_def",
                "TRAINING_DATA": "training_data",
            },
        ),
        "method": EnumDef(
            "IntegrityMethod",
            {
                "CHECKSUM": "checksum",
                "SIGNATURE": "signature",
                "PROVENANCE": "provenance",
                "BEHAVIORAL": "behavioral",
            },
        ),
        "tamper_indicator": EnumDef(
            "TamperIndicator",
            {
                "HASH_MISMATCH": "hash_mismatch",
                "UNSIGNED": "unsigned",
                "UNKNOWN_SOURCE": "unknown_source",
                "ANOMALOUS_OUTPUT": "anomalous_output",
            },
        ),
    },
    record_fields=[
        FieldDef("expected_hash", str, ""),
        FieldDef("actual_hash", str, ""),
        FieldDef("source", str, ""),
        FieldDef("verified", bool, False),
    ],
    score_field="risk_score",
    key_field="component_name",
)

# Backward-compatible re-exports
ComponentType = AISupplyChainIntegrityEngine.ComponentType
IntegrityMethod = AISupplyChainIntegrityEngine.IntegrityMethod
TamperIndicator = AISupplyChainIntegrityEngine.TamperIndicator
IntegrityRecord = AISupplyChainIntegrityEngine.Record
IntegrityAnalysis = AISupplyChainIntegrityEngine.Analysis
IntegrityReport = AISupplyChainIntegrityEngine.Report
