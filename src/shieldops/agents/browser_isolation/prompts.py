"""Browser Isolation Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class BreakoutAnalysisResult(BaseModel):
    """Structured output from LLM-assisted breakout detection."""

    summary: str = Field(description="Summary of breakout analysis")
    techniques_detected: list[str] = Field(description="Breakout techniques detected")
    risk_assessment: str = Field(description="Overall risk assessment")
    recommendations: list[str] = Field(description="Recommended containment actions")


class IsolationReportResult(BaseModel):
    """Structured output for isolation report."""

    executive_summary: str = Field(description="Executive summary of browser isolation posture")
    blocked_threats: list[str] = Field(description="Threats blocked by isolation")
    policy_gaps: list[str] = Field(description="Gaps in isolation policies")
    improvements: list[str] = Field(description="Suggested improvements")


SYSTEM_BREAKOUT = (
    "You are a browser isolation security analyst.\n"
    "Given the session data and breakout attempts:\n"
    "1. Classify breakout techniques (DOM escape, plugin exploit, etc)\n"
    "2. Assess severity and success likelihood\n"
    "3. Identify sessions requiring immediate termination\n"
    "4. Recommend policy updates to prevent future attempts"
)

SYSTEM_REPORT = (
    "You are a web security analyst generating an isolation report.\n"
    "Summarize browser isolation effectiveness:\n"
    "1. Session isolation coverage rate\n"
    "2. Breakout attempts and block rate\n"
    "3. Content sandboxing statistics\n"
    "4. Policy enforcement effectiveness"
)
