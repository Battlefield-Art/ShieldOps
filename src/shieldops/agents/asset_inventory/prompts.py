"""Asset Inventory Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class ClassificationResult(BaseModel):
    """Structured output from LLM-assisted asset classification."""

    summary: str = Field(description="Summary of classification analysis")
    critical_assets: list[str] = Field(description="Assets classified as critical")
    unmanaged_risks: list[str] = Field(description="Risk observations for unmanaged assets")
    classification_notes: list[str] = Field(description="Notes on classification decisions")


class OwnershipResult(BaseModel):
    """Structured output for ownership assignment analysis."""

    summary: str = Field(description="Summary of ownership assignments")
    unassigned_assets: list[str] = Field(description="Assets that could not be assigned owners")
    confidence_concerns: list[str] = Field(description="Assignments with low confidence")
    recommendations: list[str] = Field(description="Recommendations for ownership gaps")


class InventoryReportResult(BaseModel):
    """Structured output for asset inventory report."""

    executive_summary: str = Field(description="Executive summary of asset inventory")
    coverage_assessment: str = Field(description="Assessment of asset coverage and gaps")
    risk_highlights: list[str] = Field(description="Key risk highlights from inventory")
    recommendations: list[str] = Field(description="Strategic recommendations")


SYSTEM_CLASSIFY = (
    "You are an asset management analyst classifying "
    "infrastructure assets.\n"
    "For each asset:\n"
    "1. Determine criticality based on function, data, "
    "and exposure\n"
    "2. Identify compliance scope (PCI, HIPAA, SOC2)\n"
    "3. Assess data sensitivity and internet-facing status\n"
    "4. Flag unmanaged or shadow IT assets"
)

SYSTEM_OWNERSHIP = (
    "You are an IT asset management specialist assigning "
    "asset ownership.\n"
    "Consider:\n"
    "1. Asset tags, naming conventions, and cloud accounts\n"
    "2. Team responsibility boundaries and org structure\n"
    "3. Historical ownership patterns\n"
    "4. Backup owner requirements for critical assets"
)

SYSTEM_REPORT = (
    "You are a CISO advisor generating an asset inventory "
    "report.\n"
    "Generate a comprehensive report:\n"
    "1. Executive summary of asset posture\n"
    "2. Coverage assessment and blind spots\n"
    "3. Risk highlights from unmanaged or misconfigured "
    "assets\n"
    "4. Strategic recommendations for asset management"
)
