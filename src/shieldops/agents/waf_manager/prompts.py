"""WAF Manager — LLM prompt templates and structured output schemas."""

from pydantic import BaseModel, Field


class AttackAnalysisResult(BaseModel):
    """Structured output from LLM-assisted attack pattern analysis."""

    summary: str = Field(description="Brief summary of attack pattern analysis")
    top_categories: list[str] = Field(description="Most prevalent attack categories")
    emerging_patterns: list[str] = Field(description="Newly emerging attack patterns detected")
    risk_level: str = Field(description="Overall risk level: low, medium, high, critical")
    recommended_actions: list[str] = Field(description="Recommended defensive actions")


class RuleTuningResult(BaseModel):
    """Structured output from LLM-assisted rule tuning analysis."""

    summary: str = Field(description="Brief summary of rule tuning recommendations")
    rules_to_tighten: list[str] = Field(description="Rule IDs that should be made stricter")
    rules_to_relax: list[str] = Field(
        description="Rule IDs with high false positive rates to relax"
    )
    new_rules_needed: list[str] = Field(description="Descriptions of new rules to create")
    confidence: float = Field(description="Confidence in recommendations 0.0-1.0")


class FalsePositiveResult(BaseModel):
    """Structured output from LLM-assisted false positive analysis."""

    summary: str = Field(description="Brief summary of false positive findings")
    confirmed_fps: int = Field(description="Number of confirmed false positives")
    fp_patterns: list[str] = Field(description="Common patterns causing false positives")
    exclusion_recommendations: list[str] = Field(
        description="Recommended exclusion rules to reduce FPs"
    )
    risk_of_exclusion: str = Field(
        description="Risk level of applying exclusions: low, medium, high"
    )


SYSTEM_ATTACK_ANALYSIS = (
    "You are a WAF security analyst specializing in web attack patterns.\n"
    "Analyze the following WAF log events and identify attack patterns:\n"
    "1. Classify attacks by OWASP Top 10 category\n"
    "2. Identify coordinated attack campaigns from correlated sources\n"
    "3. Detect emerging attack patterns not covered by existing rules\n"
    "4. Assess the overall risk level to the protected applications\n"
    "5. Recommend immediate defensive actions"
)

SYSTEM_RULE_TUNING = (
    "You are a WAF rule engineer optimizing firewall rule sets.\n"
    "Based on the attack events and current rule performance:\n"
    "1. Identify rules that should be tightened (too permissive)\n"
    "2. Identify rules with excessive false positives to relax\n"
    "3. Propose new rules to close coverage gaps\n"
    "4. Balance security posture with application availability\n"
    "5. Prioritize changes by risk impact"
)

SYSTEM_FALSE_POSITIVE_ANALYSIS = (
    "You are a WAF analyst specializing in false positive reduction.\n"
    "Given the flagged events and rule hit data:\n"
    "1. Identify events that are legitimate traffic blocked by rules\n"
    "2. Find common patterns in false positives (URL, user-agent, IP)\n"
    "3. Recommend targeted exclusion rules to reduce FP rate\n"
    "4. Assess the security risk of each proposed exclusion\n"
    "5. Provide confidence scores for each FP determination"
)
