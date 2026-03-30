"""LLM prompt templates for the Firmware Security Scanner Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class FirmwareExtractOutput(BaseModel):
    """Structured output for firmware extraction analysis."""

    total_extracted: int = Field(
        description="Total firmware images extracted",
    )
    architectures_found: list[str] = Field(
        description="CPU architectures detected",
    )
    summary: str = Field(
        description="Extraction summary",
    )


class ComponentAnalysisOutput(BaseModel):
    """Structured output for component analysis."""

    total_components: int = Field(
        description="Total components identified",
    )
    outdated_count: int = Field(
        description="Count of outdated components",
    )
    reasoning: str = Field(
        description="Component analysis reasoning",
    )


class VulnScanOutput(BaseModel):
    """Structured output for vulnerability scanning."""

    total_vulns: int = Field(
        description="Total vulnerabilities found",
    )
    critical_count: int = Field(
        description="Count of critical CVEs",
    )
    reasoning: str = Field(
        description="Vulnerability scan reasoning",
    )


class CryptoCheckOutput(BaseModel):
    """Structured output for cryptographic analysis."""

    weak_algorithms: list[str] = Field(
        description="Weak algorithms found",
    )
    weak_count: int = Field(
        description="Count of weak crypto findings",
    )
    reasoning: str = Field(
        description="Crypto analysis reasoning",
    )


class FirmwareRiskOutput(BaseModel):
    """Structured output for firmware risk assessment."""

    max_risk_score: float = Field(
        description="Highest firmware risk score 0-100",
    )
    critical_devices: int = Field(
        description="Count of critically vulnerable devices",
    )
    reasoning: str = Field(
        description="Risk assessment reasoning",
    )


# ── System prompts ────────────────────────────────────

SYSTEM_EXTRACT = """\
You are an expert firmware security analyst performing \
firmware image extraction and analysis.

Given the firmware scan configuration:
1. Extract filesystem contents from firmware binaries
2. Identify OS type, CPU architecture, and boot chain
3. Detect embedded credentials and hardcoded secrets
4. Map firmware to known device models and vendors

Focus on: binary format detection, filesystem carving, \
compressed payload extraction, boot loader analysis."""

SYSTEM_COMPONENTS = """\
You are an expert firmware security analyst performing \
SBOM (Software Bill of Materials) analysis.

Given the extracted firmware contents:
1. Enumerate all software components and libraries
2. Identify version information for each component
3. Detect outdated or end-of-life software
4. Flag components with known supply chain risks

Build a comprehensive SBOM with license and \
vulnerability tracking metadata."""

SYSTEM_VULNS = """\
You are an expert firmware security analyst scanning \
for known vulnerabilities.

Given the firmware component SBOM:
1. Match components against CVE databases (NVD, VulnDB)
2. Assess exploitability in the firmware context
3. Identify publicly available exploits
4. Determine if vendor patches are available

Prioritize by CVSS score and real-world exploitability \
in IoT/OT environments."""

SYSTEM_CRYPTO = """\
You are an expert firmware security analyst checking \
cryptographic implementations.

Given the firmware binaries and extracted components:
1. Identify cryptographic algorithms in use
2. Detect weak or deprecated algorithms (DES, MD5, RC4)
3. Check key sizes against current standards
4. Find hardcoded keys and certificates

Flag any crypto that does not meet NIST or \
industry-standard minimums."""

SYSTEM_RISK = """\
You are an expert firmware security analyst assessing \
overall firmware risk.

Given the combined analysis (components, vulns, crypto):
1. Calculate composite risk scores per firmware image
2. Weight factors: vuln severity, exploitability, \
crypto weakness, component age
3. Assess business impact based on device function
4. Recommend prioritized remediation actions

Consider the operational context of IoT/OT devices \
where patching may be constrained."""
