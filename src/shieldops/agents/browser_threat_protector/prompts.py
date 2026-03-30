"""LLM prompt templates for the Browser Threat Protector Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# -- Structured output schemas -----------------------------------------


class RequestAnalysisOutput(BaseModel):
    """Structured output for request analysis."""

    total_requests: int = Field(
        description="Total requests analyzed",
    )
    suspicious_count: int = Field(
        description="Number of suspicious requests",
    )
    summary: str = Field(
        description="Analysis summary",
    )


class ReputationCheckOutput(BaseModel):
    """Structured output for reputation checking."""

    malicious_count: int = Field(
        description="Number of malicious URLs",
    )
    suspicious_count: int = Field(
        description="Number of suspicious URLs",
    )
    reasoning: str = Field(
        description="Reputation check reasoning",
    )


class IsolationOutput(BaseModel):
    """Structured output for session isolation."""

    isolated_count: int = Field(
        description="Number of sessions isolated",
    )
    container_count: int = Field(
        description="Containers spawned",
    )
    reasoning: str = Field(
        description="Isolation reasoning",
    )


class ContentScanOutput(BaseModel):
    """Structured output for content scanning."""

    threats_found: int = Field(
        description="Number of threats detected",
    )
    malicious_js: int = Field(
        description="Malicious JavaScript instances",
    )
    reasoning: str = Field(
        description="Content scan reasoning",
    )


class PolicyEnforcementOutput(BaseModel):
    """Structured output for policy enforcement."""

    blocked: int = Field(
        description="Number of requests blocked",
    )
    allowed: int = Field(
        description="Number of requests allowed",
    )
    reasoning: str = Field(
        description="Policy enforcement reasoning",
    )


# -- System prompts ----------------------------------------------------

SYSTEM_ANALYZE = """\
You are an expert browser security analyst evaluating \
web requests for threats.

Given the incoming web requests:
1. Analyze URL patterns for malicious indicators
2. Check for known phishing patterns and typosquatting
3. Evaluate request headers for suspicious behavior
4. Identify automated bot-like request patterns

Focus on: obfuscated URLs, suspicious redirects, \
unusual user agents, requests to newly registered domains."""

SYSTEM_REPUTATION = """\
You are an expert threat intelligence analyst checking \
URL reputation.

Given the web requests to check:
1. Query threat intelligence feeds for URL reputation
2. Check domain age and registration patterns
3. Evaluate SSL certificate validity and issuer
4. Cross-reference with known malware C2 infrastructure

Look for: blacklisted domains, bulletproof hosting, \
fast-flux DNS, domain generation algorithms."""

SYSTEM_ISOLATE = """\
You are an expert browser isolation specialist.

Given the suspicious URLs:
1. Determine which sessions require isolation
2. Configure pixel-streaming for visual rendering
3. Block file downloads from isolated sessions
4. Prevent clipboard and form data exfiltration

Isolate: unknown reputation sites, file downloads, \
sites with JavaScript heavy content, login pages."""

SYSTEM_SCAN = """\
You are an expert web content security analyst scanning \
for browser-based threats.

Given the isolated session content:
1. Detect malicious JavaScript (obfuscated, eval-based)
2. Identify drive-by download attempts
3. Find credential harvesting forms
4. Detect cryptominer scripts and web skimmers

Techniques: static JS analysis, DOM inspection, \
network request monitoring, behavioral analysis."""

SYSTEM_ENFORCE = """\
You are an expert security policy enforcement specialist.

Given the scan results and threat assessments:
1. Apply organization security policies
2. Block confirmed malicious content
3. Allow safe content with appropriate warnings
4. Log all enforcement decisions for audit

Balance security with user productivity."""
