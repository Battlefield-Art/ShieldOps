"""Technical Debt Ownership Mapper — map debt to owners, detect orphaned debt, rank teams by d..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TechnicalDebtOwnershipMapper = engine(
    "TechnicalDebtOwnershipMapper",
    description="Map debt to owners, detect orphaned debt, rank teams by debt burden.",
    enums={
        "debt_type": EnumDef(
            "DebtType",
            {
                "CODE": "code",
                "ARCHITECTURE": "architecture",
                "INFRASTRUCTURE": "infrastructure",
                "DOCUMENTATION": "documentation",
            },
        ),
        "ownership": EnumDef(
            "OwnershipStatus",
            {
                "OWNED": "owned",
                "SHARED": "shared",
                "ORPHANED": "orphaned",
                "DISPUTED": "disputed",
            },
        ),
        "age": EnumDef(
            "DebtAge",
            {
                "RECENT": "recent",
                "AGING": "aging",
                "LEGACY": "legacy",
                "ANCIENT": "ancient",
            },
        ),
    },
    record_fields=[
        FieldDef("team_id", str, ""),
        FieldDef("estimated_hours", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="severity_score",
    key_field="debt_id",
)

# Backward-compatible re-exports
DebtType = TechnicalDebtOwnershipMapper.DebtType
OwnershipStatus = TechnicalDebtOwnershipMapper.OwnershipStatus
DebtAge = TechnicalDebtOwnershipMapper.DebtAge
TechDebtRecord = TechnicalDebtOwnershipMapper.Record
TechDebtAnalysis = TechnicalDebtOwnershipMapper.Analysis
TechDebtReport = TechnicalDebtOwnershipMapper.Report
