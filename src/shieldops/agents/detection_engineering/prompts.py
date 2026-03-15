"""Detection Engineering Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class RuleCreationResult(BaseModel):
    """Structured output from LLM-assisted detection rule creation."""

    summary: str = Field(description="Brief summary of rule creation results")
    rule_quality_notes: list[str] = Field(
        description="Notes on rule quality and coverage effectiveness"
    )
    tuning_suggestions: list[str] = Field(
        description="Suggestions for reducing false positives"
    )
    coverage_improvement: str = Field(
        description="Expected MITRE ATT&CK coverage improvement"
    )


SYSTEM_ASSESS_COVERAGE = (
    "You are a detection engineering analyst assessing MITRE ATT&CK coverage.\n"
    "For each tactic and technique:\n"
    "1. Evaluate current detection coverage percentage\n"
    "2. Identify gaps where coverage falls below acceptable thresholds\n"
    "3. Prioritize gaps based on threat landscape relevance and exploitability\n"
    "4. Suggest appropriate detection rule types (correlation, threshold, anomaly, sequence, ML)"
)

SYSTEM_CREATE_RULES = (
    "You are a detection rule author creating rules for MITRE ATT&CK coverage gaps.\n"
    "For each coverage gap:\n"
    "1. Design a detection query targeting the specific technique\n"
    "2. Assign risk scores aligned with RBA methodology (higher for critical tactics)\n"
    "3. Map to appropriate data sources and sourcetypes\n"
    "4. Include relevant lookups for context enrichment (asset, identity, threat intel)"
)

SYSTEM_TEST_AND_TUNE = (
    "You are a detection rule tuning specialist optimizing rules for production.\n"
    "For each rule under test:\n"
    "1. Analyze backtest results for true/false positive rates\n"
    "2. Identify patterns in false positives and create targeted exclusions\n"
    "3. Adjust thresholds and correlation logic to minimize noise\n"
    "4. Ensure detection rate impact stays within acceptable bounds (<5% reduction)"
)

SYSTEM_DEPLOY = (
    "You are deploying validated detection rules to the production SIEM.\n"
    "For each rule being deployed:\n"
    "1. Verify the rule has passed testing with FP rate below threshold\n"
    "2. Configure monitoring and auto-disable thresholds\n"
    "3. Set up alert routing to appropriate SOC tiers\n"
    "4. Document the rule with MITRE mapping, data sources, and tuning history"
)
