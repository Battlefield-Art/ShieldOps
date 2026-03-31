"""LLM prompt templates and response schemas for the
Security Chaos Tester Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class ExperimentDesignOutput(BaseModel):
    """Structured output for experiment design."""

    experiments: list[dict[str, str]] = Field(
        description=("List of experiments with name, fault_type, target, and blast_radius"),
    )
    risk_assessment: str = Field(
        description="Pre-experiment risk assessment",
    )
    rollback_plans: list[str] = Field(
        description="Rollback plan for each experiment",
    )
    confidence: float = Field(
        description="Design confidence 0-1",
    )


class BehaviorAnalysisOutput(BaseModel):
    """Structured output for behavior observation analysis."""

    anomalies_detected: int = Field(
        description="Number of anomalies observed",
    )
    detection_gaps: list[str] = Field(
        description="Security controls that failed to detect",
    )
    recovery_assessment: str = Field(
        description="Assessment of recovery capabilities",
    )
    summary: str = Field(
        description="Observation summary for engineers",
    )


class ResilienceAssessmentOutput(BaseModel):
    """Structured output for resilience assessment."""

    overall_score: float = Field(
        description="Overall resilience score 0-10",
    )
    critical_failures: list[str] = Field(
        description="Components with critical failures",
    )
    improvements: list[str] = Field(
        description="Recommended resilience improvements",
    )
    rating: str = Field(
        description=("Rating: excellent/good/fair/poor/critical"),
    )


class ChaosReportOutput(BaseModel):
    """Structured output for final chaos test report."""

    executive_summary: str = Field(
        description="Executive summary of chaos campaign",
    )
    resilience_rating: str = Field(
        description="Overall resilience rating",
    )
    recommendations: list[str] = Field(
        description="Actionable recommendations",
    )
    critical_gaps: list[str] = Field(
        description="Critical security resilience gaps",
    )
    next_experiments: list[str] = Field(
        description="Suggested follow-up experiments",
    )


# --- System prompts ---


SYSTEM_EXPERIMENT_DESIGN = """\
You are an expert security chaos engineer designing \
fault injection experiments.

Given the target components and fault types:
1. Design specific experiments that test security \
control resilience
2. Define expected behavior for each experiment
3. Assess blast radius and create rollback plans
4. Prioritize by risk and coverage value

Focus on security-specific faults: credential \
revocation, firewall disruption, certificate expiry, \
and IAM policy changes."""


SYSTEM_BEHAVIOR_ANALYSIS = """\
You are an expert security observer analyzing system \
behavior during fault injection.

Given the observations from injected faults:
1. Identify deviations from expected security behavior
2. Detect gaps in security monitoring and alerting
3. Assess recovery time and failover effectiveness
4. Score detection accuracy for each control

Be precise about which security controls failed and \
which performed as expected."""


SYSTEM_RESILIENCE = """\
You are an expert security resilience assessor scoring \
system resilience after chaos testing.

Given the observations and behavior analysis:
1. Score each component on detection, response, recovery
2. Identify critical failure modes
3. Recommend specific resilience improvements
4. Rate overall security resilience posture

Consider both automated and manual response paths."""


SYSTEM_REPORT = """\
You are an expert security chaos testing reporter \
synthesizing campaign results.

Given the full chaos testing campaign results:
1. Produce an executive summary for security leadership
2. List actionable resilience improvements by priority
3. Highlight critical gaps in security controls
4. Suggest follow-up experiments for coverage

Write clearly for both security engineers and \
executive leadership."""
