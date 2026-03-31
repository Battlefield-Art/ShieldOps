"""LLM prompt templates and response schemas for the
Email Authentication Auditor Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class DomainScanOutput(BaseModel):
    """Structured output for domain scanning."""

    domains: list[dict[str, str]] = Field(
        description="Discovered domains with MX and DNS info",
    )
    total_domains: int = Field(
        description="Total domains discovered",
    )
    subdomains_found: int = Field(
        description="Subdomains with email capability",
    )
    confidence: float = Field(
        description="Scan completeness confidence 0-1",
    )


class SPFAnalysisOutput(BaseModel):
    """Structured output for SPF analysis."""

    valid_count: int = Field(
        description="Domains with valid SPF",
    )
    issues: list[str] = Field(
        description="SPF configuration issues found",
    )
    lookup_warnings: list[str] = Field(
        description="Domains exceeding DNS lookup limits",
    )
    summary: str = Field(
        description="SPF posture summary",
    )


class DMARCAnalysisOutput(BaseModel):
    """Structured output for DMARC analysis."""

    reject_count: int = Field(
        description="Domains with p=reject policy",
    )
    quarantine_count: int = Field(
        description="Domains with p=quarantine policy",
    )
    none_count: int = Field(
        description="Domains with p=none or missing DMARC",
    )
    recommendations: list[str] = Field(
        description="DMARC policy recommendations",
    )


class EmailAuthReportOutput(BaseModel):
    """Structured output for email auth report."""

    executive_summary: str = Field(
        description="Executive summary of email auth posture",
    )
    compliance_rate: float = Field(
        description="Overall compliance rate 0-100",
    )
    critical_gaps: list[str] = Field(
        description="Critical authentication gaps",
    )
    recommendations: list[str] = Field(
        description="Prioritized recommendations",
    )
    risk_level: str = Field(
        description="Overall risk: critical/high/medium/low",
    )


# --- System prompts ---


SYSTEM_DOMAIN_SCAN = """\
You are an expert email security auditor scanning \
organizational domains for authentication records.

Given the organization's domain inventory:
1. Identify all domains capable of sending email
2. Check MX records for mail-enabled domains
3. Discover subdomains used for transactional email
4. Flag domains without any authentication records

Include marketing, transactional, and corporate \
domains."""


SYSTEM_SPF_CHECK = """\
You are an expert email authentication analyst \
auditing SPF configurations.

Given SPF records for organizational domains:
1. Validate SPF syntax and mechanisms
2. Check DNS lookup count (max 10 per RFC 7208)
3. Identify overly permissive includes
4. Flag missing or broken SPF records

SPF with +all or missing records are critical \
findings."""


SYSTEM_DMARC_CHECK = """\
You are an expert DMARC policy analyst evaluating \
domain alignment and enforcement.

Given DMARC records and aggregate reports:
1. Evaluate policy strength (none/quarantine/reject)
2. Check alignment mode (strict vs relaxed)
3. Verify reporting URIs are functional
4. Recommend policy progression path

The goal is p=reject on all sending domains."""


SYSTEM_REPORT = """\
You are an expert email security reporter synthesizing \
authentication audit results for stakeholders.

Given the full audit (SPF, DKIM, DMARC) results:
1. Produce an executive summary of email auth posture
2. Highlight domains vulnerable to spoofing
3. Recommend a phased enforcement roadmap
4. Quantify brand impersonation risk

Write for both security teams and email \
administrators."""
