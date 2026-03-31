"""LLM prompt templates and response schemas for the
ML Model Scanner Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class ArtifactScanOutput(BaseModel):
    """Structured output for model artifact scanning."""

    vulnerabilities: list[dict[str, str]] = Field(
        description=("List of vulnerabilities with type, severity, and description"),
    )
    unsafe_operations: list[str] = Field(
        description="Unsafe deserialization operations detected",
    )
    pickle_risk: bool = Field(
        description="Whether pickle deserialization risk exists",
    )
    risk_level: str = Field(
        description="Risk level: critical/high/medium/low/info",
    )


class ProvenanceCheckOutput(BaseModel):
    """Structured output for provenance verification."""

    verified: bool = Field(
        description="Whether provenance chain is verified",
    )
    source_trusted: bool = Field(
        description="Whether source repository is trusted",
    )
    signing_valid: bool = Field(
        description="Whether model signature is valid",
    )
    concerns: list[str] = Field(
        description="Provenance concerns identified",
    )


class BackdoorDetectionOutput(BaseModel):
    """Structured output for backdoor detection analysis."""

    backdoor_detected: bool = Field(
        description="Whether backdoor indicators found",
    )
    indicators: list[dict[str, str]] = Field(
        description="Backdoor indicators with type and confidence",
    )
    confidence: float = Field(
        description="Detection confidence 0-1",
    )
    affected_layers: list[str] = Field(
        description="Model layers with suspicious patterns",
    )


class ModelScanReportOutput(BaseModel):
    """Structured output for final scan report."""

    executive_summary: str = Field(
        description="Executive summary of model scan results",
    )
    critical_findings: list[str] = Field(
        description="Critical security findings",
    )
    recommendations: list[str] = Field(
        description="Actionable remediation recommendations",
    )
    overall_risk: str = Field(
        description="Overall risk rating: critical/high/medium/low",
    )


# --- System prompts ---


SYSTEM_SCAN = """\
You are an expert ML model security scanner analyzing \
model artifacts for supply chain risks.

Given the model artifact metadata and scan results:
1. Identify unsafe deserialization patterns (pickle, \
joblib, torch.load without weights_only)
2. Check for known CVEs in model frameworks
3. Assess serialization format security (prefer \
safetensors over pickle)
4. Flag any code execution vectors in model files

Focus on real-world attack vectors: model poisoning, \
trojan weights, and supply chain injection."""


SYSTEM_PROVENANCE = """\
You are an expert ML supply chain security analyst \
verifying model provenance and integrity.

Given the model artifact and its provenance records:
1. Verify the chain of custody from training to \
deployment
2. Check cryptographic signatures and hashes
3. Assess whether training data sources are documented
4. Verify SBOM (Software Bill of Materials) completeness

Trust but verify: unsigned models from unknown sources \
are high risk."""


SYSTEM_BACKDOOR = """\
You are an expert ML security researcher detecting \
model backdoors and poisoning attacks.

Given the model architecture and weight analysis:
1. Look for trigger patterns in input preprocessing
2. Detect anomalous weight distributions in specific \
layers
3. Identify potential data poisoning signatures
4. Check for hidden functionality in custom layers

Be thorough but precise: false positives erode trust \
in the scanning pipeline."""


SYSTEM_REPORT = """\
You are an expert security analyst synthesizing ML \
model scan results into an actionable report.

Given the full scan results (artifacts, vulnerabilities, \
provenance, backdoor analysis):
1. Produce an executive summary for security leadership
2. Prioritize critical findings by exploitability
3. Provide specific remediation steps per finding
4. Rate overall model supply chain risk posture

Write clearly for both ML engineers and security teams."""
