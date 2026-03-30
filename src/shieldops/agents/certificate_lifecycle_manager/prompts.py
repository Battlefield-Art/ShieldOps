"""Certificate Lifecycle Manager Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class ExpiryAnalysisResult(BaseModel):
    """Structured output from LLM-assisted expiry analysis."""

    summary: str = Field(description="Summary of certificate expiry landscape")
    critical_certs: list[str] = Field(description="Certificates requiring immediate attention")
    risk_assessment: str = Field(description="Overall risk from expiring certificates")
    recommendations: list[str] = Field(description="Recommendations for certificate hygiene")


class ComplianceAnalysisResult(BaseModel):
    """Structured output for certificate compliance analysis."""

    summary: str = Field(description="Summary of compliance validation results")
    non_compliant_certs: list[str] = Field(description="Certificates failing compliance checks")
    compliance_issues: list[str] = Field(description="Specific compliance issues found")
    remediation_steps: list[str] = Field(description="Steps to achieve full compliance")


class CLMReportResult(BaseModel):
    """Structured output for certificate lifecycle report."""

    executive_summary: str = Field(description="Executive summary of certificate posture")
    risk_posture: str = Field(description="Current certificate risk posture")
    trends: list[str] = Field(description="Certificate lifecycle trends observed")
    recommendations: list[str] = Field(description="Strategic recommendations")


SYSTEM_EXPIRY_ANALYSIS = (
    "You are a PKI analyst assessing certificate expiry risk.\n"
    "For each certificate:\n"
    "1. Evaluate urgency based on days remaining\n"
    "2. Assess impact of expiry on services\n"
    "3. Identify certificates needing immediate renewal\n"
    "4. Flag wildcard and CA certificates as higher priority"
)

SYSTEM_COMPLIANCE = (
    "You are a security compliance analyst validating "
    "TLS/SSL certificate configurations.\n"
    "Check for:\n"
    "1. Weak key algorithms (RSA < 2048, deprecated curves)\n"
    "2. Insecure protocol versions (TLSv1.0, TLSv1.1)\n"
    "3. Invalid or incomplete certificate chains\n"
    "4. Self-signed certificates in production"
)

SYSTEM_REPORT = (
    "You are a CISO advisor generating a certificate "
    "lifecycle management report.\n"
    "Generate a comprehensive report:\n"
    "1. Executive summary of certificate posture\n"
    "2. Current risk from expiring/misconfigured certs\n"
    "3. Trends in certificate hygiene\n"
    "4. Strategic recommendations for PKI improvement"
)
