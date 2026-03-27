"""LLM prompts and schemas for Web App Scanner Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field


class InjectionAnalysisOutput(BaseModel):
    """Structured output for injection analysis."""

    vulnerable: bool = Field(description="Whether endpoint is vulnerable")
    category: str = Field(description="Vulnerability category (sqli/xss/ssrf)")
    severity: str = Field(description="Severity: critical/high/medium/low")
    remediation: str = Field(description="Specific remediation guidance")


class WebScanReportOutput(BaseModel):
    """Structured output for web scan report."""

    executive_summary: str = Field(description="Executive summary of web app scan")
    owasp_coverage: dict[str, str] = Field(description="OWASP Top 10 coverage status")
    top_findings: list[str] = Field(description="Top vulnerability findings")
    recommendations: list[str] = Field(description="Prioritized remediation steps")


SYSTEM_INJECTION_ANALYSIS = """\
You are a web application security expert analyzing \
potential injection vulnerabilities.

Given the endpoint, parameter, payload, and response:
1. Determine if the endpoint is truly vulnerable
2. Classify the vulnerability category
3. Assess severity based on exploitability and impact
4. Provide specific remediation guidance

Distinguish true positives from false positives."""


SYSTEM_WEB_REPORT = """\
You are a senior web application penetration tester \
writing a scan report.

Given the crawl results, injection tests, auth tests, \
and access control findings:
1. Summarize the web application security posture
2. Map findings to OWASP Top 10 categories
3. Highlight the most critical findings
4. Provide actionable remediation recommendations

Be specific to the application tested."""
