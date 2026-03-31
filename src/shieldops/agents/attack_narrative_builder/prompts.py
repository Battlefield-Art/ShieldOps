"""Attack Narrative Builder Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class TimelineInsight(BaseModel):
    """Structured output from timeline correlation."""

    summary: str = Field(
        description="Brief timeline correlation overview",
    )
    key_events: list[str] = Field(
        description="Key events in the attack timeline",
    )
    temporal_patterns: list[str] = Field(
        description="Temporal patterns detected",
    )


class ChainInsight(BaseModel):
    """Structured output from attack chain reconstruction."""

    summary: str = Field(
        description="Attack chain reconstruction overview",
    )
    critical_links: list[str] = Field(
        description="Critical links in the kill chain",
    )
    attack_vectors: list[str] = Field(
        description="Identified attack vectors",
    )


class NarrativeInsight(BaseModel):
    """Structured output from narrative building."""

    summary: str = Field(
        description="Attack narrative overview",
    )
    threat_actor_profile: list[str] = Field(
        description="Inferred threat actor characteristics",
    )
    recommendations: list[str] = Field(
        description="Defense recommendations",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of attack narrative",
    )
    key_findings: list[str] = Field(
        description="Key findings for incident response",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_ANALYZE = (
    "You are a threat intelligence analyst reconstructing "
    "an attack narrative from security events.\n"
    "1. Correlate events by time, host, and user\n"
    "2. Identify kill chain phases and progression\n"
    "3. Map techniques to MITRE ATT&CK framework\n"
    "4. Build a coherent attack story from evidence"
)

SYSTEM_REPORT = (
    "You are a senior incident responder generating an "
    "executive attack narrative report.\n"
    "1. Summarize the attack timeline and progression\n"
    "2. Map all MITRE ATT&CK techniques observed\n"
    "3. Highlight the most critical attack phases\n"
    "4. Recommend detection and prevention improvements"
)
