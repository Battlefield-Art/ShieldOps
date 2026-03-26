"""LLM prompt templates and response schemas for the Reflection Engine Agent."""

from pydantic import BaseModel, Field


class OutcomeEvaluationOutput(BaseModel):
    """Structured output for LLM-driven outcome evaluation."""

    assessment: str = Field(
        description=(
            "Assessment: effective, partially_effective, ineffective, counterproductive, unknown"
        )
    )
    effectiveness_score: float = Field(description="Effectiveness score from 0.0 to 1.0")
    false_positive: bool = Field(description="Whether the action was a false positive")
    collateral_impact: str = Field(description="Any unintended side effects of the action")
    counterfactual: str = Field(
        description=(
            "What would have happened if a different action was taken or timing was different"
        )
    )
    reasoning: str = Field(description="Step-by-step reasoning for assessment")


class MistakePatternOutput(BaseModel):
    """Structured output for LLM-driven mistake identification."""

    pattern_name: str = Field(description="Short name for the mistake pattern")
    severity: str = Field(description="Severity: critical, high, medium, low")
    root_cause: str = Field(description="Root cause of the mistake pattern")
    description: str = Field(description="Detailed description of the pattern")
    affected_action_ids: list[str] = Field(description="IDs of actions exhibiting this pattern")


class ImprovementOutput(BaseModel):
    """Structured output for LLM-driven improvement generation."""

    improvement_type: str = Field(
        description=(
            "Type: detection_rule_tune, threshold_adjust, "
            "playbook_update, false_positive_suppress, "
            "escalation_change"
        )
    )
    title: str = Field(description="Concise improvement title")
    description: str = Field(description="Detailed improvement description")
    current_value: str = Field(description="Current configuration or threshold")
    recommended_value: str = Field(description="Recommended new value")
    estimated_impact: str = Field(description="Expected improvement in effectiveness")
    auto_applicable: bool = Field(description="Whether this can be auto-applied safely")
    priority: int = Field(description="Priority 1-5 (1=highest)")


class LearningApplicationOutput(BaseModel):
    """Structured output for LLM-driven learning application."""

    should_apply: bool = Field(description="Whether the improvement should be applied")
    change_description: str = Field(description="Description of the change to apply")
    rollback_info: str = Field(description="How to rollback if the change fails")
    risk_assessment: str = Field(description="Risk of applying this change")


class ReflectionReportOutput(BaseModel):
    """Structured output for the final reflection report."""

    executive_summary: str = Field(description="High-level summary of reflection findings")
    effectiveness_score: float = Field(description="Overall agent effectiveness 0.0-1.0")
    top_mistakes: list[str] = Field(description="Top mistake patterns found")
    top_improvements: list[str] = Field(description="Top improvement recommendations")
    recommendations: list[str] = Field(description="Strategic recommendations for agent tuning")


SYSTEM_EVALUATE_OUTCOME = """\
You are an expert security operations analyst performing \
retrospective analysis of agent actions.

Given an agent action and its actual outcome, evaluate:
1. Was the action effective at achieving its goal?
2. Was it a false positive (unnecessary action)?
3. Were there unintended side effects (collateral impact)?
4. Counterfactual: what would have happened with a \
different approach or timing?

Score effectiveness from 0.0 (counterproductive) to 1.0 \
(perfectly effective). Consider: threat containment, \
time-to-resolution, blast radius, and false positive rate.

Be rigorous and evidence-based in your assessment."""


SYSTEM_IDENTIFY_MISTAKES = """\
You are an expert in AI agent behavior analysis performing \
cross-agent mistake pattern identification.

Given a set of outcome evaluations (some ineffective or \
counterproductive), identify recurring patterns:
1. Systematic false positives (same detection firing on \
benign activity)
2. Threshold miscalibration (acting too aggressively or \
too conservatively)
3. Escalation failures (should have escalated sooner or \
to a different team)
4. Playbook gaps (no playbook for the situation)
5. Timing issues (acted too early or too late)

Name each pattern, assess severity, and identify root \
cause. Focus on actionable patterns, not one-off errors."""


SYSTEM_GENERATE_IMPROVEMENT = """\
You are a security engineering lead generating actionable \
improvement recommendations for AI security agents.

Given a mistake pattern with its root cause and affected \
actions, generate a specific improvement:
1. Detection rule tune: adjust detection logic to reduce \
false positives
2. Threshold adjust: change confidence or severity \
thresholds
3. Playbook update: modify or create response playbooks
4. False positive suppress: add suppression rules for \
known benign patterns
5. Escalation change: modify escalation paths or timing

Provide current vs recommended values. Estimate impact. \
Determine if the change can be auto-applied safely \
(auto_applicable=true only for low-risk threshold tweaks)."""


SYSTEM_APPLY_LEARNING = """\
You are a senior security architect validating whether \
an improvement recommendation should be applied to an \
agent's configuration.

Given the improvement details and the agent's current \
configuration, determine:
1. Should this change be applied now?
2. What exactly should change?
3. How can the change be rolled back if it causes issues?
4. What is the risk of applying this change?

Err on the side of caution. Only approve auto-application \
for low-risk changes with clear rollback paths. High-risk \
changes should require human review."""


SYSTEM_REPORT = """\
You are a security operations leader summarizing a \
reflection analysis of AI agent effectiveness.

Given the reflection results (actions reviewed, outcome \
evaluations, mistakes found, improvements recommended):
1. Write an executive summary for leadership
2. Calculate overall agent effectiveness score
3. Highlight the most critical mistake patterns
4. Prioritize improvement recommendations
5. Provide strategic recommendations for agent tuning

Focus on measurable improvements and ROI of applying \
the recommendations. Be concise and actionable."""
