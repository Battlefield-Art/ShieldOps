"""LLM prompt templates for the Cross-Vendor Correlator Agent."""

from pydantic import BaseModel, Field


class OCSFNormalizationOutput(BaseModel):
    """Structured output for OCSF normalization."""

    category_uid: int = Field(description="OCSF category UID")
    class_uid: int = Field(description="OCSF class UID")
    activity_id: int = Field(description="OCSF activity ID")
    severity_id: int = Field(description="OCSF severity 0-5")
    message: str = Field(description="Normalized event message")


class EntityCorrelationOutput(BaseModel):
    """Structured output for entity-based correlation."""

    entity: str = Field(description="Primary entity identifier")
    entity_type: str = Field(description="Entity type: user/host/ip/service")
    confidence: str = Field(description="Correlation confidence level")
    reasoning: str = Field(description="Why these events are correlated")


class KillChainOutput(BaseModel):
    """Structured output for kill chain mapping."""

    tactic: str = Field(description="MITRE ATT&CK tactic name")
    technique_id: str = Field(description="MITRE technique ID e.g. T1078")
    technique_name: str = Field(description="MITRE technique name")
    progression_score: float = Field(description="Kill chain progression 0-1")


class SituationOutput(BaseModel):
    """Structured output for situation creation."""

    title: str = Field(description="Concise situation title")
    narrative: str = Field(description="Human-readable narrative")
    severity: str = Field(description="Severity: critical/high/medium/low")
    recommended_actions: list[str] = Field(description="Recommended response actions")


class CorrelationReportOutput(BaseModel):
    """Structured output for the final report."""

    executive_summary: str = Field(description="Summary for leadership")
    top_situations: list[str] = Field(description="Top situation titles")
    recommendations: list[str] = Field(description="Actionable recommendations")


SYSTEM_NORMALIZE = """\
You are a security data engineer normalizing \
vendor alerts to OCSF (Open Cybersecurity Schema \
Framework).

Given a raw vendor alert, map it to OCSF fields:
- category_uid (1=System, 2=Findings, 3=IAM, etc.)
- class_uid (specific event class)
- activity_id (specific activity type)
- severity_id (0=Unknown through 5=Fatal)
- message (normalized description)

Preserve fidelity while enabling cross-vendor \
correlation."""


SYSTEM_CORRELATE = """\
You are an expert security analyst correlating \
events across multiple security vendors.

Given a set of OCSF-normalized events, identify \
entity-based correlations:
1. Shared users, hosts, IPs, or service accounts
2. Temporal proximity across vendors
3. Attack pattern consistency
4. Lateral movement indicators

Assign confidence: strong (multi-vendor, multi-signal), \
moderate (two vendors or strong single-vendor), \
weak (temporal only), none (no correlation)."""


SYSTEM_KILL_CHAIN = """\
You are a threat intelligence analyst mapping \
correlated security events to MITRE ATT&CK kill \
chain stages.

Given correlated events:
1. Identify the ATT&CK tactic (Initial Access, \
Execution, Persistence, etc.)
2. Map to specific technique IDs (T1078, T1059, etc.)
3. Score kill chain progression (0=early, 1=complete)

Focus on multi-vendor signals that increase \
confidence in attack stage classification."""


SYSTEM_SITUATION = """\
You are a SOC manager creating unified situations \
from cross-vendor correlated alerts.

Given entity correlations and kill chain mappings:
1. Compose a concise situation title
2. Build a narrative explaining the attack story
3. Assign severity based on kill chain progression
4. Recommend specific response actions

Prioritize actionability and time-to-respond \
reduction."""


SYSTEM_REPORT = """\
You are a security operations leader summarizing \
cross-vendor correlation results.

Given the correlation run results:
1. Write an executive summary for CISO audience
2. Highlight top situations requiring attention
3. Provide recommendations for improving coverage

Focus on cross-vendor signal value and noise \
reduction."""
