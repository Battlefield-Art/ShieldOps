"""SAST Scanner Agent — LLM prompt templates and output schemas."""

from pydantic import BaseModel, Field


class ASTAnalysisOutput(BaseModel):
    """Structured output from LLM-assisted AST analysis."""

    summary: str = Field(
        description="Brief summary of AST-level findings",
    )
    logic_flaws: list[str] = Field(
        description="Logic-level flaws missed by regex patterns",
    )
    dataflow_issues: list[str] = Field(
        description="Dataflow taint paths identified",
    )
    false_positive_ids: list[str] = Field(
        description="Finding IDs likely to be false positives",
    )


class PrioritizationOutput(BaseModel):
    """Structured output from LLM-assisted prioritization."""

    summary: str = Field(
        description="Brief prioritization summary",
    )
    top_risk_ids: list[str] = Field(
        description="Finding IDs representing highest risk",
    )
    exploitable_ids: list[str] = Field(
        description="Finding IDs confirmed exploitable",
    )
    priority_scores: dict[str, float] = Field(
        description="Finding ID to priority score mapping",
    )
    risk_narrative: str = Field(
        description="Overall risk narrative for stakeholders",
    )


SYSTEM_AST_ANALYSIS = (
    "You are a static analysis expert performing deep "
    "AST-level code review.\n"
    "Go beyond regex pattern matching to find:\n"
    "1. Taint propagation from user input to sinks\n"
    "2. Control flow that bypasses validation\n"
    "3. Type confusion and implicit conversions\n"
    "4. Resource leaks and use-after-free patterns\n"
    "5. Concurrency bugs (race conditions, deadlocks)\n"
    "6. AI-specific: prompt injection via data flow"
)

SYSTEM_PRIORITIZATION = (
    "You are a security analyst prioritizing SAST findings "
    "for developer remediation.\n"
    "Score each finding by:\n"
    "1. Exploitability — can an attacker reach this code?\n"
    "2. Impact — what damage results from exploitation?\n"
    "3. Confidence — is this a true positive?\n"
    "4. Fix complexity — how hard is remediation?\n"
    "5. Attack chain potential — does it chain with others?"
)
