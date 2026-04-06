"""Agent Skill Acquisition Engine — tracks which SRE skills agents acquire at each iteration."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentSkillAcquisitionEngine = engine(
    "AgentSkillAcquisitionEngine",
    description="Tracks which SRE skills agents acquire at each iteration.",
    enums={
        "domain": EnumDef(
            "SkillDomain",
            {
                "DIAGNOSIS": "diagnosis",
                "REMEDIATION": "remediation",
                "TRIAGE": "triage",
                "PREVENTION": "prevention",
            },
        ),
        "status": EnumDef(
            "AcquisitionStatus",
            {
                "NOT_STARTED": "not_started",
                "LEARNING": "learning",
                "ACQUIRED": "acquired",
                "MASTERED": "mastered",
            },
        ),
        "dependency": EnumDef(
            "SkillDependency",
            {
                "PREREQUISITE": "prerequisite",
                "COREQUISITE": "corequisite",
                "INDEPENDENT": "independent",
                "SEQUENTIAL": "sequential",
            },
        ),
    },
    record_fields=[
        FieldDef("skill_name", str, ""),
        FieldDef("iteration_acquired", int, 0),
        FieldDef("prerequisite_skill", str, ""),
        FieldDef("description", str, ""),
    ],
    score_field="proficiency_score",
    key_field="agent_id",
)

# Backward-compatible re-exports
SkillDomain = AgentSkillAcquisitionEngine.SkillDomain
AcquisitionStatus = AgentSkillAcquisitionEngine.AcquisitionStatus
SkillDependency = AgentSkillAcquisitionEngine.SkillDependency
SkillAcquisitionRecord = AgentSkillAcquisitionEngine.Record
SkillAcquisitionAnalysis = AgentSkillAcquisitionEngine.Analysis
SkillAcquisitionReport = AgentSkillAcquisitionEngine.Report
