"""LLM prompt templates and response schemas for the
Digital Forensics Lab Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class ArtifactAnalysisOutput(BaseModel):
    """Structured output for artifact analysis."""

    artifacts_found: int = Field(
        description="Number of forensic artifacts found",
    )
    categories: list[str] = Field(
        description="Artifact categories discovered",
    )
    suspicious_items: list[str] = Field(
        description="Artifacts flagged as suspicious",
    )
    confidence: float = Field(
        description="Analysis confidence score 0-1",
    )


class IOCExtractionOutput(BaseModel):
    """Structured output for IOC extraction."""

    iocs_extracted: int = Field(
        description="Number of IOCs extracted",
    )
    ioc_types: list[str] = Field(
        description="Types of IOCs found (IP, hash, domain, etc.)",
    )
    mitre_mappings: list[str] = Field(
        description="MITRE ATT&CK technique mappings",
    )
    summary: str = Field(
        description="IOC extraction summary",
    )


class TimelineConstructionOutput(BaseModel):
    """Structured output for timeline construction."""

    events_ordered: int = Field(
        description="Number of timeline events ordered",
    )
    attack_phases: list[str] = Field(
        description="Identified attack phases",
    )
    pivot_points: list[str] = Field(
        description="Key pivot points in the timeline",
    )
    narrative: str = Field(
        description="Attack narrative from timeline",
    )


class ForensicReportOutput(BaseModel):
    """Structured output for forensic report."""

    executive_summary: str = Field(
        description="Executive summary of forensic findings",
    )
    attack_vector: str = Field(
        description="Identified initial attack vector",
    )
    recommendations: list[str] = Field(
        description="Remediation recommendations",
    )
    evidence_integrity: str = Field(
        description="Evidence integrity status: verified/partial/compromised",
    )


# --- System prompts ---


SYSTEM_ARTIFACTS = """\
You are an expert digital forensics analyst examining \
artifacts from compromised systems.

Given the acquired evidence and extracted artifacts:
1. Classify artifacts by category: filesystem, registry, \
memory, network, browser, application
2. Identify artifacts indicating persistence, lateral \
movement, or data exfiltration
3. Correlate artifacts across evidence sources
4. Assess significance of each artifact to the investigation

Maintain chain of custody awareness: document every \
analytical step for legal admissibility."""


SYSTEM_IOCS = """\
You are an expert threat intelligence analyst extracting \
indicators of compromise from forensic evidence.

Given forensic artifacts and analysis results:
1. Extract IOCs: IPs, domains, file hashes, URLs, \
email addresses, registry keys
2. Map each IOC to MITRE ATT&CK techniques
3. Score confidence based on corroborating evidence
4. Deduplicate and prioritize IOCs for threat hunting

Focus on high-confidence IOCs that can drive immediate \
detection and blocking rules."""


SYSTEM_TIMELINE = """\
You are an expert forensic investigator constructing \
attack timelines from digital evidence.

Given artifacts, IOCs, and system events:
1. Order events chronologically across all evidence sources
2. Identify attack phases: initial access, execution, \
persistence, lateral movement, exfiltration
3. Highlight pivot points where the attacker changed tactics
4. Construct a coherent attack narrative

Precision in timestamps is critical: note time zone \
discrepancies and clock skew."""


SYSTEM_REPORT = """\
You are an expert forensic reporter producing \
investigation reports for incident response teams.

Given the complete forensic investigation data:
1. Produce an executive summary of the compromise
2. Document the attack vector and kill chain
3. List remediation recommendations by priority
4. Certify evidence integrity and chain of custody

Write for legal review: be precise, factual, and \
avoid speculation beyond the evidence."""
