"""Data Sensitivity Classifier Engine — track data classification accuracy and coverage."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

DataSensitivityClassifierEngine = engine(
    "DataSensitivityClassifierEngine",
    description="Track data classification accuracy, coverage, and sensitivity tiers.",
    enums={
        "sensitivity_tier": EnumDef(
            "SensitivityTier",
            {
                "TOP_SECRET": "top_secret",
                "CONFIDENTIAL": "confidential",
                "INTERNAL": "internal",
                "PUBLIC": "public",
                "UNCLASSIFIED": "unclassified",
            },
        ),
        "data_regulation": EnumDef(
            "DataRegulation",
            {
                "GDPR": "gdpr",
                "HIPAA": "hipaa",
                "PCI_DSS": "pci_dss",
                "CCPA": "ccpa",
                "SOX": "sox",
            },
        ),
        "classification_method": EnumDef(
            "ClassificationMethod",
            {
                "REGEX": "regex",
                "ML_MODEL": "ml_model",
                "LLM": "llm",
                "MANUAL": "manual",
                "INHERITED": "inherited",
            },
        ),
    },
    record_fields=[
        FieldDef("confidence", float, 0.0),
        FieldDef("records_scanned", int, 0),
        FieldDef("findings_count", int, 0),
    ],
    key_field="asset_id",
)

# Backward-compatible re-exports
SensitivityTier = DataSensitivityClassifierEngine.SensitivityTier
DataRegulation = DataSensitivityClassifierEngine.DataRegulation
ClassificationMethod = DataSensitivityClassifierEngine.ClassificationMethod
DataSensitivityClassifierRecord = DataSensitivityClassifierEngine.Record
DataSensitivityClassifierAnalysis = DataSensitivityClassifierEngine.Analysis
DataSensitivityClassifierReport = DataSensitivityClassifierEngine.Report
