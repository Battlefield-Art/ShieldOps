"""SCA Dependency Checker Agent — LLM prompt templates and output schemas."""

from pydantic import BaseModel, Field


class CVEAnalysisOutput(BaseModel):
    """Structured output from LLM-assisted CVE analysis."""

    summary: str = Field(
        description="Brief CVE risk summary",
    )
    exploitable_cves: list[str] = Field(
        description="CVE IDs likely exploitable in context",
    )
    false_positive_ids: list[str] = Field(
        description="CVE IDs unlikely to be exploitable",
    )
    upgrade_paths: list[str] = Field(
        description="Recommended upgrade paths",
    )
    transitive_risks: list[str] = Field(
        description="Transitive dependency chain risks",
    )


class LicenseAnalysisOutput(BaseModel):
    """Structured output from LLM-assisted license analysis."""

    summary: str = Field(
        description="Brief license compliance summary",
    )
    violations: list[str] = Field(
        description="License compatibility violations",
    )
    copyleft_risks: list[str] = Field(
        description="Copyleft infection risks",
    )
    recommendations: list[str] = Field(
        description="Remediation recommendations",
    )


SYSTEM_CVE_ANALYSIS = (
    "You are a software composition analyst evaluating "
    "dependency vulnerabilities in context.\n"
    "For each CVE:\n"
    "1. Assess if the vulnerable function is reachable\n"
    "2. Check if network exposure enables exploitation\n"
    "3. Identify transitive chains amplifying risk\n"
    "4. Recommend minimal safe upgrade paths\n"
    "5. Flag zero-day or actively-exploited CVEs\n"
    "6. Consider AI/ML library-specific attack vectors"
)

SYSTEM_LICENSE_ANALYSIS = (
    "You are a software license compliance analyst.\n"
    "Evaluate:\n"
    "1. GPL/AGPL copyleft infection in commercial code\n"
    "2. Attribution requirements for BSD/MIT/Apache\n"
    "3. Patent clause implications (Apache 2.0)\n"
    "4. Dual-license ambiguity resolution\n"
    "5. Export control restrictions on crypto libraries"
)
