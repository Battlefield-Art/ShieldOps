"""DAST Runner Agent — LLM prompt templates and output schemas."""

from pydantic import BaseModel, Field


class CrawlAnalysisOutput(BaseModel):
    """Structured output from LLM-assisted crawl analysis."""

    summary: str = Field(
        description="Brief summary of crawl findings",
    )
    high_value_endpoints: list[str] = Field(
        description="Endpoints most likely to have vulns",
    )
    auth_weaknesses: list[str] = Field(
        description="Authentication weaknesses identified",
    )
    attack_surface_notes: list[str] = Field(
        description="Attack surface observations",
    )


class FuzzAnalysisOutput(BaseModel):
    """Structured output from LLM-assisted fuzz analysis."""

    summary: str = Field(
        description="Brief summary of fuzzing results",
    )
    confirmed_vulns: list[str] = Field(
        description="Confirmed vulnerability IDs",
    )
    false_positive_ids: list[str] = Field(
        description="Finding IDs likely false positives",
    )
    exploitation_paths: list[str] = Field(
        description="Potential exploitation paths",
    )
    risk_narrative: str = Field(
        description="Overall risk narrative",
    )


SYSTEM_CRAWL_ANALYSIS = (
    "You are a web application security tester analyzing "
    "crawl results to identify attack surface.\n"
    "Focus on:\n"
    "1. Endpoints accepting user input (forms, APIs)\n"
    "2. Authentication and session management flows\n"
    "3. File upload and download handlers\n"
    "4. Admin and debug endpoints exposed\n"
    "5. API versioning gaps and deprecated endpoints\n"
    "6. CORS misconfigurations and header issues"
)

SYSTEM_FUZZ_ANALYSIS = (
    "You are a penetration tester analyzing DAST fuzzing "
    "results for confirmed vulnerabilities.\n"
    "For each finding:\n"
    "1. Verify if the response indicates real exploitation\n"
    "2. Check for false positives from WAF/error pages\n"
    "3. Identify chained attack paths\n"
    "4. Assess business logic bypass potential\n"
    "5. Rate confidence and exploitability"
)
