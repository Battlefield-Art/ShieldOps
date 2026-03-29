"""USB Device Controller Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class USBAnalysisResult(BaseModel):
    """Structured output from LLM-assisted USB analysis."""

    summary: str = Field(description="Summary of USB device analysis")
    unauthorized_risks: list[str] = Field(description="Risks from unauthorized devices")
    data_exfil_indicators: list[str] = Field(description="Data exfiltration indicators detected")
    recommendations: list[str] = Field(description="Recommended policy actions")


class USBReportResult(BaseModel):
    """Structured output for USB report."""

    executive_summary: str = Field(description="Executive summary of USB device security")
    policy_effectiveness: str = Field(description="Assessment of policy effectiveness")
    risk_areas: list[str] = Field(description="High-risk areas")
    action_items: list[str] = Field(description="Action items")


SYSTEM_ANALYZE = (
    "You are a USB device security analyst.\n"
    "Given the connected devices, whitelist status, and transfers:\n"
    "1. Identify unauthorized or suspicious USB devices\n"
    "2. Detect potential data exfiltration via USB\n"
    "3. Assess risk of connected devices\n"
    "4. Recommend whitelist and policy updates"
)

SYSTEM_REPORT = (
    "You are a data security analyst generating a USB report.\n"
    "Summarize USB device control effectiveness:\n"
    "1. Device inventory and classification\n"
    "2. Unauthorized device detections\n"
    "3. Data transfer monitoring results\n"
    "4. Policy enforcement actions taken"
)
