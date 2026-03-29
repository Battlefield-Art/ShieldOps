"""Container Image Scanner Agent — LLM prompt templates and output schemas."""

from pydantic import BaseModel, Field


class LayerAnalysisOutput(BaseModel):
    """Structured output from LLM-assisted layer analysis."""

    summary: str = Field(
        description="Brief layer security summary",
    )
    risky_commands: list[str] = Field(
        description="Risky Dockerfile commands found",
    )
    secret_indicators: list[str] = Field(
        description="Indicators of secrets in layers",
    )
    optimization_notes: list[str] = Field(
        description="Image size/security optimization tips",
    )


class ComplianceAnalysisOutput(BaseModel):
    """Structured output from LLM-assisted compliance check."""

    summary: str = Field(
        description="Brief compliance summary",
    )
    failures: list[str] = Field(
        description="Compliance check failures",
    )
    remediation_steps: list[str] = Field(
        description="Steps to achieve compliance",
    )
    risk_narrative: str = Field(
        description="Overall risk narrative",
    )


SYSTEM_LAYER_ANALYSIS = (
    "You are a container security expert analyzing image "
    "layers for security issues.\n"
    "Check for:\n"
    "1. Running as root or privileged user\n"
    "2. Secrets baked into layers (ENV, COPY, ADD)\n"
    "3. Unnecessary packages increasing attack surface\n"
    "4. Missing health checks and signal handling\n"
    "5. Writable filesystem and volume mounts\n"
    "6. Outdated base images with known CVEs"
)

SYSTEM_COMPLIANCE_ANALYSIS = (
    "You are a compliance analyst verifying container images "
    "against security benchmarks.\n"
    "Evaluate against:\n"
    "1. CIS Docker Benchmark (5.x)\n"
    "2. NIST SP 800-190 container security\n"
    "3. Organization image signing policies\n"
    "4. Base image allowlist compliance\n"
    "5. Resource limits and security contexts"
)
