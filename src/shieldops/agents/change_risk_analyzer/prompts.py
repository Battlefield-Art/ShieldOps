"""Change Risk Analyzer Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class RiskAnalysisResult(BaseModel):
    """Structured output from LLM-assisted risk analysis."""

    summary: str = Field(description="Brief summary of the risk analysis")
    key_concerns: list[str] = Field(description="Top concerns identified in the change")
    mitigation_suggestions: list[str] = Field(
        description="Suggestions to mitigate identified risks"
    )
    confidence_note: str = Field(description="Note on confidence level and data quality")


class BlastRadiusResult(BaseModel):
    """Structured output from LLM-assisted blast radius prediction."""

    summary: str = Field(description="Brief summary of blast radius analysis")
    critical_paths: list[str] = Field(description="Most critical dependency paths at risk")
    worst_case_scenario: str = Field(description="Description of worst-case failure scenario")
    recommended_safeguards: list[str] = Field(description="Safeguards to limit blast radius")


class RecommendationResult(BaseModel):
    """Structured output from LLM-assisted recommendation generation."""

    summary: str = Field(description="Brief summary of recommendations")
    approval_rationale: str = Field(description="Rationale for the approval decision")
    rollback_strategy: str = Field(description="Recommended rollback strategy")
    deployment_tips: list[str] = Field(description="Tips for safer deployment execution")


SYSTEM_COLLECT_CHANGE = (
    "You are a change management analyst collecting and validating change requests.\n"
    "For each change request:\n"
    "1. Validate that all required fields are present and well-formed\n"
    "2. Classify the change type accurately (deployment, config, infra, DB migration)\n"
    "3. Identify which services and environments are affected\n"
    "4. Flag any missing information that could impact risk assessment"
)

SYSTEM_ANALYZE_DIFF = (
    "You are a code review analyst examining change diffs for risk indicators.\n"
    "For each diff:\n"
    "1. Analyze file types changed (schema files, config, application code, tests)\n"
    "2. Identify breaking changes, API modifications, or dependency updates\n"
    "3. Check for security-sensitive changes (auth, encryption, permissions)\n"
    "4. Assess test coverage adequacy for the changes"
)

SYSTEM_ASSESS_RISK = (
    "You are a deployment risk analyst scoring change risk.\n"
    "For each change:\n"
    "1. Evaluate timing risk (day of week, time of day, traffic patterns)\n"
    "2. Assess complexity risk (diff size, services affected, change type)\n"
    "3. Check historical failure patterns for similar changes\n"
    "4. Calculate a composite risk score with confidence interval"
)

SYSTEM_PREDICT_BLAST_RADIUS = (
    "You are a reliability engineer predicting blast radius of changes.\n"
    "For each change:\n"
    "1. Trace service dependency paths to identify all downstream impacts\n"
    "2. Estimate user-facing impact based on service traffic patterns\n"
    "3. Identify data at risk (databases, caches, payment systems)\n"
    "4. Predict cascading failure scenarios and recovery timelines"
)

SYSTEM_RECOMMEND = (
    "You are a change advisory board analyst generating deployment recommendations.\n"
    "For each change:\n"
    "1. Determine the appropriate approval gate (auto-approve, review, block)\n"
    "2. Identify required reviewers based on risk level and affected systems\n"
    "3. Design a rollback plan with estimated recovery time\n"
    "4. Recommend canary deployment and monitoring strategies"
)

SYSTEM_REPORT = (
    "You are a change risk reporting analyst generating executive summaries.\n"
    "For the complete analysis:\n"
    "1. Summarize overall risk posture across all pending changes\n"
    "2. Highlight the highest-risk changes requiring immediate attention\n"
    "3. Provide actionable recommendations for the deployment pipeline\n"
    "4. Track risk trends compared to recent deployment history"
)
