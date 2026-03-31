"""LLM prompt templates and response schemas for the
Wireless Security Auditor Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class EncryptionAuditOutput(BaseModel):
    """Structured output for encryption audit."""

    non_compliant_count: int = Field(
        description="Number of non-compliant access points",
    )
    weaknesses: list[dict[str, str]] = Field(
        description=("List of encryption weaknesses with ap_id, protocol, and severity"),
    )
    upgrade_recommendations: list[str] = Field(
        description="Encryption upgrade recommendations",
    )
    summary: str = Field(
        description="Encryption audit summary",
    )


class RogueDetectionOutput(BaseModel):
    """Structured output for rogue AP detection."""

    rogue_aps: list[dict[str, str]] = Field(
        description=("List of rogue APs with ssid, bssid, classification, and threat_level"),
    )
    evil_twins_found: int = Field(
        description="Number of evil twin APs detected",
    )
    confidence: float = Field(
        description="Detection confidence 0-1",
    )
    mitigation_steps: list[str] = Field(
        description="Immediate mitigation steps",
    )


class WirelessRiskOutput(BaseModel):
    """Structured output for wireless risk assessment."""

    risk_score: float = Field(
        description="Aggregate wireless risk score 0-10",
    )
    critical_findings: list[str] = Field(
        description="Critical wireless security findings",
    )
    attack_vectors: list[str] = Field(
        description="Potential wireless attack vectors",
    )
    compliance_gaps: list[str] = Field(
        description="Compliance gaps identified",
    )


class WirelessReportOutput(BaseModel):
    """Structured output for final wireless audit report."""

    executive_summary: str = Field(
        description="Executive summary of wireless audit",
    )
    total_rogues: int = Field(
        description="Total rogue APs detected",
    )
    recommendations: list[str] = Field(
        description="Actionable recommendations",
    )
    compliance_status: str = Field(
        description="Overall compliance: pass/fail/partial",
    )
    effectiveness_rating: str = Field(
        description="Audit effectiveness: high/medium/low",
    )


# --- System prompts ---


SYSTEM_ENCRYPTION_AUDIT = """\
You are an expert wireless security auditor evaluating \
encryption configurations across access points.

Given the scanned access points and their configurations:
1. Identify access points using weak encryption (WEP, \
open, WPA without AES)
2. Flag non-compliance with WPA3 or enterprise standards
3. Detect misconfigured RADIUS/802.1X settings
4. Recommend specific protocol upgrades per AP

Prioritize by exploitability and data exposure risk."""


SYSTEM_ROGUE_DETECTION = """\
You are an expert wireless security analyst detecting \
rogue and evil twin access points.

Given the discovered networks and known authorized SSIDs:
1. Identify unauthorized access points by BSSID/SSID
2. Detect evil twin attacks (matching SSID, different BSSID)
3. Classify each unknown AP (rogue, neighbor, evil twin)
4. Assess threat level based on signal strength and location

Focus on APs that could intercept corporate traffic."""


SYSTEM_RISK_ASSESSMENT = """\
You are an expert wireless security risk assessor \
evaluating the overall wireless attack surface.

Given the encryption audit and rogue AP findings:
1. Calculate aggregate wireless risk score
2. Identify potential attack vectors (deauth, KARMA, \
evil twin, credential theft)
3. Assess compliance with PCI-DSS, HIPAA, and SOC 2 \
wireless requirements
4. Map findings to CIS wireless security benchmarks

Consider both internal and external threat actors."""


SYSTEM_REPORT = """\
You are an expert wireless security reporter synthesizing \
audit findings for security leadership.

Given the full wireless security audit results:
1. Produce an executive summary with key metrics
2. List actionable recommendations by priority
3. Report compliance status against relevant standards
4. Rate overall wireless security posture

Write clearly for both network engineers and \
security executives."""
