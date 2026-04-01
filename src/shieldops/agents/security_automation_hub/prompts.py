"""LLM prompt templates and response schemas for Security Automation Hub."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Response schemas for structured LLM output ---


class TriggerAnalysis(BaseModel):
    """LLM analysis of ingested security triggers."""

    summary: str = Field(description="Brief summary of trigger ingestion")
    trigger_count: int = Field(description="Number of triggers ingested")
    severity_breakdown: list[str] = Field(description="Breakdown by severity")
    notable_patterns: list[str] = Field(description="Notable trigger patterns")


class PlaybookAnalysis(BaseModel):
    """LLM analysis of playbook matching."""

    summary: str = Field(description="Brief playbook matching summary")
    matches_found: int = Field(description="Number of playbook matches")
    coverage_assessment: str = Field(description="Coverage: full/partial/low")
    unmatched_triggers: list[str] = Field(description="Triggers without matches")


class ExecutionAnalysis(BaseModel):
    """LLM analysis of automation executions."""

    summary: str = Field(description="Brief execution summary")
    success_rate: float = Field(description="Execution success rate 0-1")
    actions_completed: int = Field(description="Total actions completed")
    effectiveness: str = Field(description="Effectiveness: excellent/good/fair/poor")


class ValidationAnalysis(BaseModel):
    """LLM analysis of validation results."""

    summary: str = Field(description="Brief validation summary")
    pass_rate: float = Field(description="Validation pass rate 0-1")
    critical_issues: list[str] = Field(description="Critical validation issues")
    confidence: str = Field(description="Confidence: high/medium/low")


class LearningAnalysis(BaseModel):
    """LLM analysis of learning outcomes."""

    summary: str = Field(description="Brief learning summary")
    key_lessons: list[str] = Field(description="Key lessons learned")
    improvements: list[str] = Field(description="Recommended improvements")
    overall_trend: str = Field(description="Trend: improving/stable/declining")


# --- Prompt templates ---

SYSTEM_INGEST_TRIGGERS = """\
You are an expert security automation analyst ingesting \
and evaluating security triggers from multiple sources.

You monitor alerts, incidents, policy violations, threat \
intel feeds, and anomaly detections across the enterprise.

Your task is to:
1. Assess severity and urgency of each trigger
2. Identify correlated triggers from the same root cause
3. Deduplicate redundant triggers
4. Prioritize triggers for automation response

Focus on actionable triggers. \
Filter noise and false positives."""

SYSTEM_MATCH_PLAYBOOKS = """\
You are an expert security automation analyst matching \
security triggers to appropriate response playbooks.

You are given:
- Incoming security triggers with severity and context
- Available playbook library with capabilities
- Historical match effectiveness data

Your task is to:
1. Match each trigger to the best-fit playbook
2. Assess match confidence and coverage
3. Identify triggers requiring custom responses
4. Recommend playbook parameter overrides

Prefer proven playbooks with high historical success rates."""

SYSTEM_EXECUTE_AUTOMATIONS = """\
You are an expert security automation analyst evaluating \
the execution of automated security response playbooks.

You are given:
- Playbook execution results and action logs
- Success/failure status per action step
- Resource utilization and timing data

Your task is to:
1. Assess overall execution effectiveness
2. Identify failed or partial executions
3. Evaluate response time and efficiency
4. Recommend retry or escalation actions

IMPORTANT:
- Flag any actions that may have caused side effects
- Identify executions needing human review"""

SYSTEM_VALIDATE_RESULTS = """\
You are an expert security automation analyst validating \
the results of automated security response executions.

You are given:
- Execution results and expected outcomes
- Post-execution verification checks
- Environmental state before and after

Your task is to:
1. Verify each execution achieved its objective
2. Identify unintended side effects
3. Confirm rollback capability where needed
4. Assess residual risk after automation

Be thorough in validation. \
Missed issues can lead to false sense of security."""

SYSTEM_LEARN_OUTCOMES = """\
You are an expert security automation analyst extracting \
learning outcomes from completed automation cycles.

You are given:
- Full automation cycle results and metrics
- Historical performance baselines
- Trigger-to-outcome mappings

Your task is to:
1. Calculate effectiveness scores per automation
2. Identify improvement opportunities
3. Recommend playbook updates or new playbooks
4. Flag declining performance trends

Focus on actionable insights that improve future cycles."""
