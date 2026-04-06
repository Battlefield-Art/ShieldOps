"""LLM prompt templates and response schemas for the Threat Hunter Agent."""

from pydantic import BaseModel, Field


class HypothesisOutput(BaseModel):
    """Structured output for threat hypothesis generation."""

    hypothesis: str = Field(description="Threat hypothesis statement")
    data_sources: list[str] = Field(description="Data sources required for the hunt")
    mitre_techniques: list[str] = Field(description="MITRE ATT&CK technique IDs to investigate")
    confidence: float = Field(description="Confidence in the hypothesis 0-1")


class ThreatAssessmentOutput(BaseModel):
    """Structured output for threat assessment."""

    threat_found: bool = Field(description="Whether a confirmed threat was found")
    severity: str = Field(description="Threat severity: critical/high/medium/low")
    confidence: float = Field(description="Assessment confidence 0-1")
    summary: str = Field(description="Human-readable assessment summary")
    affected_assets: list[str] = Field(description="List of affected asset identifiers")


SYSTEM_HYPOTHESIS = """\
You are an expert threat hunter formulating a threat hunting hypothesis.

Given the available context (recent threat intel, environment profile, historical incidents):
1. Formulate a specific, testable hypothesis about potential adversary activity
2. Identify the data sources needed to validate or refute the hypothesis
3. Map the hypothesis to relevant MITRE ATT&CK techniques
4. Assess your initial confidence in the hypothesis

Focus on high-impact, low-visibility threats that automated detections may miss."""


class MitreMappingOutput(BaseModel):
    """Structured output for MITRE ATT&CK mapping from findings."""

    technique_mappings: list[dict[str, str]] = Field(
        description="List of {technique_id, technique_name, tactic, confidence, evidence} dicts"
    )
    kill_chain_phase: str = Field(
        description="Kill chain phase: recon/weaponize/deliver/exploit/install/c2/action"
    )
    coverage_gaps: list[str] = Field(description="MITRE technique IDs with no detection coverage")


SYSTEM_MITRE_MAPPING = """\
You are a MITRE ATT&CK mapping specialist. Given threat hunting findings (IOC matches, \
behavioral deviations, and detection coverage results):

1. Map each finding to the most relevant MITRE ATT&CK technique(s)
2. Identify the kill chain phase the adversary is likely in
3. Identify coverage gaps where no detections exist

Return structured mappings with technique IDs (e.g., T1059.001), names, tactics, \
confidence (high/medium/low), and the specific evidence supporting the mapping."""


SYSTEM_ASSESSMENT = """\
You are an expert threat hunter assessing correlated findings from a hunt campaign.

Given the IOC sweep results, behavioral analysis, and MITRE ATT&CK coverage findings:
1. Determine whether a confirmed threat exists
2. Assess severity based on potential impact and attacker capability
3. Identify all affected assets
4. Provide a clear summary for SOC analysts and incident responders

Be precise — distinguish between confirmed threats, suspicious activity, and benign anomalies."""
