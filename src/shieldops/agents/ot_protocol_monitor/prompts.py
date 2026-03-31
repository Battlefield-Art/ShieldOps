"""OT Protocol Monitor Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class AnomalyInsight(BaseModel):
    """Structured output from OT anomaly analysis."""

    summary: str = Field(
        description="Brief OT anomaly overview",
    )
    critical_anomalies: list[str] = Field(
        description="Critical protocol anomalies found",
    )
    affected_zones: list[str] = Field(
        description="OT network zones affected",
    )


class ThreatInsight(BaseModel):
    """Structured output from OT threat classification."""

    summary: str = Field(
        description="OT threat classification overview",
    )
    attack_vectors: list[str] = Field(
        description="Identified ICS attack vectors",
    )
    mitre_tactics: list[str] = Field(
        description="MITRE ICS ATT&CK tactics matched",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of OT security analysis",
    )
    key_findings: list[str] = Field(
        description="Key findings for OT security team",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_ANOMALY = (
    "You are an OT/ICS security analyst reviewing "
    "protocol anomalies.\n"
    "1. Identify abnormal Modbus/DNP3/OPC-UA patterns\n"
    "2. Flag unauthorized write operations to PLCs\n"
    "3. Detect unusual function codes and register access\n"
    "4. Spot reconnaissance and lateral movement in OT zones"
)

SYSTEM_REPORT = (
    "You are an OT security advisor generating an "
    "executive ICS threat analysis report.\n"
    "1. Summarize threats by protocol and severity\n"
    "2. Highlight devices requiring immediate attention\n"
    "3. Quantify the scope of OT-based attacks\n"
    "4. Recommend ICS security hardening steps"
)
