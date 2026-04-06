"""SIEM Migration Engine — track migration and rule translation."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

SiemMigrationEngine = engine(
    "SiemMigrationEngine",
    description="Track SIEM migration and rule translation.",
    enums={
        "phase": EnumDef(
            "MigrationPhase",
            {
                "DISCOVERY": "discovery",
                "MAPPING": "mapping",
                "TRANSLATION": "translation",
                "TESTING": "testing",
                "CUTOVER": "cutover",
            },
        ),
        "source_format": EnumDef(
            "RuleFormat",
            {
                "SPLUNK_SPL": "splunk_spl",
                "ELASTIC_EQL": "elastic_eql",
                "SIGMA": "sigma",
                "KQL": "kql",
                "YARA_L": "yara_l",
            },
        ),
        "status": EnumDef(
            "TranslationStatus",
            {
                "PENDING": "pending",
                "TRANSLATED": "translated",
                "VALIDATED": "validated",
                "FAILED": "failed",
                "SKIPPED": "skipped",
            },
        ),
    },
    score_field="fidelity_score",
    key_field="rule_id",
)

# Backward-compatible re-exports
MigrationPhase = SiemMigrationEngine.MigrationPhase
RuleFormat = SiemMigrationEngine.RuleFormat
TranslationStatus = SiemMigrationEngine.TranslationStatus
MigrationRecord = SiemMigrationEngine.Record
MigrationAnalysis = SiemMigrationEngine.Analysis
MigrationReport = SiemMigrationEngine.Report
