"""Adversarial Scenario Generator Engine — track generated adversarial test scenarios."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AdversarialScenarioGeneratorEngine = engine(
    "AdversarialScenarioGeneratorEngine",
    description="Track and analyze generated adversarial test scenarios.",
    enums={
        "scenario_type": EnumDef(
            "ScenarioType",
            {
                "PROMPT_INJECTION": "prompt_injection",
                "CREDENTIAL_THEFT": "credential_theft",
                "LATERAL_MOVEMENT": "lateral_movement",
                "DATA_EXFILTRATION": "data_exfiltration",
                "PRIVILEGE_ESCALATION": "privilege_escalation",
            },
        ),
        "target_surface": EnumDef(
            "TargetSurface",
            {
                "LLM_API": "llm_api",
                "MCP_SERVER": "mcp_server",
                "SERVICE_ACCOUNT": "service_account",
                "CLOUD_IAM": "cloud_iam",
                "KUBERNETES_RBAC": "kubernetes_rbac",
            },
        ),
        "scenario_complexity": EnumDef(
            "ScenarioComplexity",
            {
                "BASIC": "basic",
                "INTERMEDIATE": "intermediate",
                "ADVANCED": "advanced",
                "APT_LEVEL": "apt_level",
                "NOVEL": "novel",
            },
        ),
    },
    record_fields=[
        FieldDef("mitre_techniques", str, ""),
        FieldDef("success_probability", float, 0.0),
        FieldDef("defense_coverage", float, 0.0),
    ],
    key_field="scenario_name",
)

# Backward-compatible re-exports
ScenarioType = AdversarialScenarioGeneratorEngine.ScenarioType
TargetSurface = AdversarialScenarioGeneratorEngine.TargetSurface
ScenarioComplexity = AdversarialScenarioGeneratorEngine.ScenarioComplexity
ScenarioRecord = AdversarialScenarioGeneratorEngine.Record
ScenarioAnalysis = AdversarialScenarioGeneratorEngine.Analysis
ScenarioReport = AdversarialScenarioGeneratorEngine.Report
