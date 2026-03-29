"""IaC Security Scanner Agent — LLM prompt templates and output schemas."""

from pydantic import BaseModel, Field


class MisconfigAnalysisOutput(BaseModel):
    """Structured output from LLM-assisted misconfig analysis."""

    summary: str = Field(
        description="Brief misconfiguration summary",
    )
    logic_flaws: list[str] = Field(
        description="Logic-level IaC flaws beyond static rules",
    )
    privilege_escalation_paths: list[str] = Field(
        description="IAM privilege escalation paths found",
    )
    remediation_snippets: list[str] = Field(
        description="Code snippets for remediation",
    )


class PolicyAnalysisOutput(BaseModel):
    """Structured output from LLM-assisted policy evaluation."""

    summary: str = Field(
        description="Brief policy evaluation summary",
    )
    violations: list[str] = Field(
        description="Policy violations identified",
    )
    auto_fixable: list[str] = Field(
        description="Findings that can be auto-remediated",
    )
    risk_narrative: str = Field(
        description="Overall risk narrative",
    )
    priority_scores: dict[str, float] = Field(
        description="Finding ID to priority score mapping",
    )


SYSTEM_MISCONFIG_ANALYSIS = (
    "You are an infrastructure security expert analyzing "
    "IaC templates for deep security issues.\n"
    "Go beyond static rule matching:\n"
    "1. Find IAM privilege escalation via role chaining\n"
    "2. Detect cross-resource trust that creates backdoors\n"
    "3. Identify blast radius of misconfigured resources\n"
    "4. Check for drift between declared and actual state\n"
    "5. Evaluate network segmentation effectiveness\n"
    "6. Assess data encryption key management"
)

SYSTEM_POLICY_ANALYSIS = (
    "You are a cloud security policy analyst evaluating "
    "IaC against organizational security policies.\n"
    "Evaluate:\n"
    "1. CIS benchmarks for AWS/GCP/Azure\n"
    "2. SOC 2 / HIPAA / PCI DSS requirements\n"
    "3. Organization-specific security guardrails\n"
    "4. Least privilege principle compliance\n"
    "5. Defense-in-depth architecture patterns"
)
