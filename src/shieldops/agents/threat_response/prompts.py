"""Threat Response Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class ThreatClassificationResult(BaseModel):
    """Structured output from LLM-assisted threat classification."""

    summary: str = Field(description="Summary of threat classification")
    threat_type: str = Field(
        description="Classified threat type (e.g., malware, phishing, lateral_movement)"
    )
    severity: str = Field(
        description="Assessed severity: critical, high, medium, low"
    )
    mitre_tactics: list[str] = Field(
        description="MITRE ATT&CK tactics identified"
    )
    urgency_assessment: str = Field(
        description="Assessment of response urgency"
    )


class PlaybookSelectionResult(BaseModel):
    """Structured output for playbook selection rationale."""

    summary: str = Field(description="Summary of playbook selection")
    selected_playbook: str = Field(
        description="Name of the selected playbook"
    )
    rationale: str = Field(
        description="Rationale for playbook selection"
    )
    customizations: list[str] = Field(
        description="Recommended customizations to the standard playbook"
    )


class ResponseReportResult(BaseModel):
    """Structured output for threat response report."""

    executive_summary: str = Field(description="Executive summary")
    threat_timeline: list[str] = Field(
        description="Timeline of threat detection and response"
    )
    actions_taken: list[str] = Field(
        description="Summary of all actions taken"
    )
    lessons_learned: list[str] = Field(
        description="Lessons learned for future responses"
    )


SYSTEM_CLASSIFY = (
    "You are a threat intelligence analyst classifying security threats.\n"
    "Given the threat indicators:\n"
    "1. Classify the overall threat type (malware, phishing, brute force, etc.)\n"
    "2. Assess severity based on indicator context and potential impact\n"
    "3. Map to MITRE ATT&CK tactics and techniques\n"
    "4. Determine response urgency — is immediate containment required?"
)

SYSTEM_PLAYBOOK = (
    "You are a SOC manager selecting the appropriate response playbook.\n"
    "Given the threat classification:\n"
    "1. Select the most appropriate response playbook\n"
    "2. Explain the rationale for selection\n"
    "3. Recommend any customizations based on the specific threat context\n"
    "4. Identify any additional playbooks that may need to be activated"
)

SYSTEM_REPORT = (
    "You are a CISO advisor generating a threat response after-action report.\n"
    "Generate a comprehensive report:\n"
    "1. Executive summary of the threat and response\n"
    "2. Timeline from detection through remediation\n"
    "3. All containment and eradication actions taken\n"
    "4. Lessons learned and recommendations for future prevention"
)
