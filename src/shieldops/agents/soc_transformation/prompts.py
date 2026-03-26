"""LLM prompt templates and response schemas for SOC Transformation."""

from pydantic import BaseModel, Field

# ── Response Schemas ──────────────────────────────────


class AssessmentOutput(BaseModel):
    """LLM output for SOC maturity assessment."""

    maturity_level: str = Field(
        description=("Current maturity: reactive/proactive/adaptive/autonomous"),
    )
    score: float = Field(
        description="Numeric maturity score 0-100",
    )
    pain_points: list[str] = Field(
        description="Top pain points in the current SOC",
    )
    strengths: list[str] = Field(
        description="Current SOC strengths to preserve",
    )
    coverage_gaps: list[str] = Field(
        description="Detection/response coverage gaps",
    )
    recommendations: list[str] = Field(
        description="Prioritized improvement recommendations",
    )
    reasoning: str = Field(
        description="Assessment reasoning",
    )


class ArchitectureOutput(BaseModel):
    """LLM output for target architecture design."""

    primary_siem: str = Field(
        description="Recommended primary SIEM platform",
    )
    secondary_tools: list[str] = Field(
        description="Complementary tools (SOAR, TI, etc.)",
    )
    data_pipeline_design: str = Field(
        description="Data pipeline architecture description",
    )
    detection_strategy: str = Field(
        description="Detection engineering strategy",
    )
    automation_targets: list[str] = Field(
        description="Workflows to automate first",
    )
    cost_reduction_pct: float = Field(
        description="Estimated cost reduction percentage",
    )
    mttd_improvement_pct: float = Field(
        description="Estimated MTTD improvement percentage",
    )
    mttr_improvement_pct: float = Field(
        description="Estimated MTTR improvement percentage",
    )
    rationale: str = Field(
        description="Architecture design rationale",
    )


class MigrationPlanOutput(BaseModel):
    """LLM output for migration planning."""

    steps: list[dict[str, str]] = Field(
        description=(
            "Ordered steps: title, description, target, estimated_hours, risk_level, rollback_plan"
        ),
    )
    prerequisites: list[str] = Field(
        description="Prerequisites before migration starts",
    )
    risk_summary: str = Field(
        description="Overall risk assessment for the migration",
    )
    phases: int = Field(
        description="Number of migration phases",
    )
    reasoning: str = Field(
        description="Migration planning reasoning",
    )


class RuleTranslationOutput(BaseModel):
    """LLM output for detection rule translation."""

    translated_rule: str = Field(
        description="Rule translated to the target query language",
    )
    target_language: str = Field(
        description="Target query language (SPL/EQL/KQL/native)",
    )
    logic_preserved: bool = Field(
        description="Whether detection logic is fully preserved",
    )
    caveats: list[str] = Field(
        description="Translation caveats or limitations",
    )
    mitre_technique: str = Field(
        description="MITRE technique the rule detects",
    )
    confidence: float = Field(
        description="Translation confidence 0-1",
    )


class ValidationOutput(BaseModel):
    """LLM output for post-migration validation."""

    overall_passed: bool = Field(
        description="Whether the migration meets acceptance criteria",
    )
    checks: list[dict[str, str]] = Field(
        description=("Validation checks: name, passed, details, metric_before, metric_after"),
    )
    remaining_risks: list[str] = Field(
        description="Residual risks after migration",
    )
    recommendations: list[str] = Field(
        description="Post-migration tuning recommendations",
    )
    confidence: float = Field(
        description="Confidence in the validation 0-1",
    )


# ── System Prompts ────────────────────────────────────


SYSTEM_SOC_ASSESSMENT = """\
You are a SOC transformation expert assessing an organization's \
current Security Operations Center maturity.

Evaluate the SOC across these dimensions:
1. Detection coverage — MITRE ATT&CK technique coverage percentage
2. Response automation — percentage of alerts handled without humans
3. Data pipeline efficiency — ingestion cost vs. detection value
4. Analyst productivity — alerts per analyst, false positive rate
5. Tool consolidation — number of overlapping tools

Maturity levels:
- Reactive: manual triage, siloed tools, high MTTD/MTTR
- Proactive: some automation, threat hunting, tuned detections
- Adaptive: ML-driven detection, automated response, integrated tools
- Autonomous: AI agents handle most operations, humans supervise

Be specific about pain points and quantify gaps where possible."""


SYSTEM_TARGET_ARCHITECTURE = """\
You are a SOC architect designing the target-state architecture \
for a SOC transformation.

Given the current assessment, design an architecture that:
1. Consolidates SIEM tools to reduce cost and complexity
2. Optimizes data pipelines (tiered storage, smart routing)
3. Deploys detection-as-code with CI/CD for rules
4. Automates tier-1 triage and common response workflows
5. Integrates AI/ML for anomaly detection and investigation

Recommend specific platforms and justify each choice. Estimate \
cost savings, MTTD improvement, and MTTR improvement as \
percentages. Prioritize quick wins that show value in 30 days."""


SYSTEM_MIGRATION_PLANNING = """\
You are a SOC migration planner creating a phased migration plan.

Build an ordered list of migration steps that:
1. Start with data pipeline (foundation for everything else)
2. Migrate detection rules with logic-preserving translation
3. Deploy automation workflows incrementally
4. Run old and new systems in parallel during validation
5. Include rollback plans for every step

Categorize each step as: siem_consolidation, data_pipeline, \
detection_rules, workflow_automation, or response_playbooks.

Estimate hours and risk level (low/medium/high) for each step. \
Minimize downtime and detection gaps during migration."""


SYSTEM_RULE_TRANSLATION = """\
You are a detection engineering expert specializing in SIEM rule \
translation across platforms.

Translate the given detection rule to the target query language \
while preserving:
1. Detection logic — exact same conditions trigger the alert
2. Field mappings — map vendor-specific fields correctly
3. Temporal constraints — time windows, aggregation periods
4. Severity and confidence — preserve risk context
5. MITRE ATT&CK mapping — maintain technique references

Supported translations:
- Splunk SPL -> Elastic EQL/KQL
- Elastic EQL -> Splunk SPL
- Any -> ShieldOps native (Python-based detection)
- Sigma rules -> any target platform

Flag any logic that cannot be perfectly translated."""


SYSTEM_VALIDATION = """\
You are a SOC transformation validator verifying that a \
migration met its objectives.

Validate against these criteria:
1. Detection parity — all original rules fire on test data
2. Data completeness — no log sources lost during migration
3. Latency — ingestion-to-alert time meets SLAs
4. Cost — actual cost vs. projected savings
5. Automation — workflow coverage meets targets
6. Coverage — MITRE ATT&CK coverage maintained or improved

Report each check as passed/failed with before/after metrics. \
Flag any regressions that need immediate attention."""
