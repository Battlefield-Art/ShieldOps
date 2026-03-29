"""Packet Inspector Agent — LLM prompt templates and output schemas."""

from pydantic import BaseModel, Field


class PayloadAnalysisOutput(BaseModel):
    """LLM output for payload inspection."""

    summary: str = Field(description="Brief payload analysis summary")
    risk_level: str = Field(description="Risk: critical, high, medium, low, benign")
    suspicious_indicators: list[str] = Field(description="Indicators of suspicious payload content")
    protocol_anomalies: list[str] = Field(description="Protocol-level anomalies detected")
    exfiltration_likelihood: float = Field(description="Likelihood of data exfiltration (0-1)")


class TLSValidationOutput(BaseModel):
    """LLM output for TLS certificate analysis."""

    summary: str = Field(description="TLS validation summary")
    risk_level: str = Field(description="Risk: critical, high, medium, low")
    weak_ciphers: list[str] = Field(description="Identified weak or deprecated cipher suites")
    certificate_issues: list[str] = Field(description="Certificate chain or validity issues")
    downgrade_risk: bool = Field(description="Whether TLS downgrade attack is possible")


class ThreatDetectionOutput(BaseModel):
    """LLM output for threat detection from packets."""

    summary: str = Field(description="Threat detection summary")
    threats: list[str] = Field(description="Detected threats with brief descriptions")
    mitre_techniques: list[str] = Field(description="MITRE ATT&CK technique IDs")
    confidence: float = Field(description="Overall detection confidence 0-1")
    reasoning: str = Field(description="Detailed reasoning for detections")


class ReportOutput(BaseModel):
    """LLM output for final inspection report."""

    executive_summary: str = Field(description="Executive summary of packet inspection")
    key_findings: list[str] = Field(description="Top findings from the inspection")
    recommendations: list[str] = Field(description="Recommended security actions")
    risk_rating: str = Field(description="Overall risk: critical, high, medium, low")


SYSTEM_PAYLOAD_ANALYSIS = (
    "You are a network security analyst performing "
    "deep packet inspection on captured traffic.\n"
    "Given the following payload data:\n"
    "1. Identify the application-layer protocol and "
    "validate header conformance\n"
    "2. Check for obfuscated or encoded payloads — "
    "base64, XOR, custom encoding\n"
    "3. Detect command-and-control beaconing patterns "
    "in payload content\n"
    "4. Identify data exfiltration indicators — DNS "
    "tunneling, HTTP POST with encoded bodies\n"
    "5. Flag suspicious protocol misuse — HTTP on "
    "non-standard ports, DNS over HTTPS anomalies"
)

SYSTEM_TLS_VALIDATION = (
    "You are a TLS security specialist reviewing "
    "certificate and cipher suite configurations.\n"
    "Given the following TLS metadata:\n"
    "1. Validate certificate chain completeness and "
    "issuer trust hierarchy\n"
    "2. Check for expired, self-signed, or revoked "
    "certificates\n"
    "3. Identify weak cipher suites — RC4, DES, "
    "export-grade, NULL ciphers\n"
    "4. Detect TLS version downgrade risks — SSLv3, "
    "TLS 1.0, TLS 1.1 still in use\n"
    "5. Analyze JA3/JA3S fingerprints for known "
    "malware or suspicious client profiles"
)

SYSTEM_THREAT_DETECTION = (
    "You are a senior SOC analyst detecting network "
    "threats from deep packet inspection data.\n"
    "Given the combined payload and TLS analysis:\n"
    "1. Correlate payload anomalies with known attack "
    "patterns — SQL injection, shell commands, "
    "exploit payloads\n"
    "2. Map detections to MITRE ATT&CK techniques "
    "(T1071 Application Layer Protocol, T1048 "
    "Exfiltration Over Alternative Protocol)\n"
    "3. Assess lateral movement indicators from "
    "internal-to-internal traffic\n"
    "4. Identify encrypted channel abuse — normal "
    "TLS masking C2 traffic\n"
    "5. Provide confidence scores and recommended "
    "containment actions"
)

SYSTEM_REPORT = (
    "You are a network security lead producing an "
    "executive-level packet inspection report.\n"
    "Given the full inspection results:\n"
    "1. Summarize key threats and their business "
    "impact in non-technical language\n"
    "2. Highlight critical TLS issues requiring "
    "immediate remediation\n"
    "3. Recommend firewall rules, IDS signatures, "
    "or policy changes\n"
    "4. Prioritize actions by risk severity and "
    "ease of implementation\n"
    "5. Provide an overall risk rating for the "
    "inspected traffic window"
)
