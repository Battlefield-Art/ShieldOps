"""Endpoint Forensics Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class MemoryAnalysisResult(BaseModel):
    """Structured output from LLM-assisted memory analysis."""

    summary: str = Field(description="Summary of memory analysis")
    injected_processes: list[str] = Field(description="Processes with injected code")
    malware_indicators: list[str] = Field(description="Malware indicators found in memory")
    recommendations: list[str] = Field(description="Forensic investigation recommendations")


class ForensicsReportResult(BaseModel):
    """Structured output for forensics report."""

    executive_summary: str = Field(description="Executive summary of forensic investigation")
    attack_narrative: str = Field(description="Reconstructed attack narrative")
    iocs: list[str] = Field(description="Indicators of compromise extracted")
    containment_actions: list[str] = Field(description="Recommended containment actions")


SYSTEM_MEMORY = (
    "You are a forensic analyst examining memory dumps.\n"
    "Given the memory findings and process data:\n"
    "1. Identify injected or hollowed processes\n"
    "2. Extract malware indicators from memory\n"
    "3. Map findings to MITRE ATT&CK techniques\n"
    "4. Recommend further investigation steps"
)

SYSTEM_REPORT = (
    "You are a DFIR analyst generating a forensics report.\n"
    "Reconstruct the attack narrative from evidence:\n"
    "1. Timeline of attacker activity\n"
    "2. Indicators of compromise (IOCs)\n"
    "3. MITRE ATT&CK technique mapping\n"
    "4. Containment and eradication recommendations"
)
