"""LLM prompt templates and response schemas for the Network Traffic Analyzer."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AnomalyOutput(BaseModel):
    """Structured output for anomaly detection."""

    anomaly_type: str = Field(
        description="Type: lateral_movement/c2_beacon/"
        "data_exfiltration/dns_tunneling/"
        "port_scan/protocol_anomaly/"
        "bandwidth_spike/beaconing"
    )
    severity: str = Field(description="Severity: critical/high/medium/low")
    confidence: float = Field(description="Confidence score 0.0-1.0")
    description: str = Field(description="Description of the anomaly")
    mitre_tactic: str = Field(description="MITRE ATT&CK tactic ID")


class ThreatOutput(BaseModel):
    """Structured output for threat classification."""

    threat_name: str = Field(description="Name of the identified threat")
    severity: str = Field(description="Severity: critical/high/medium/low")
    confidence: float = Field(description="Confidence score 0.0-1.0")
    kill_chain_phase: str = Field(
        description="Kill chain phase: recon/weaponize/deliver/exploit/install/c2/actions"
    )
    recommended_action: str = Field(description="Recommended response action")


class ProtocolOutput(BaseModel):
    """Structured output for protocol analysis."""

    findings: list[str] = Field(description="Key findings for protocol behavior")
    risk_level: str = Field(description="Risk: critical/high/medium/low/none")
    recommendation: str = Field(description="Recommendation for the protocol")


class ReportOutput(BaseModel):
    """Structured output for traffic analysis report."""

    executive_summary: str = Field(description="One-paragraph executive summary")
    key_findings: list[str] = Field(description="Top findings from the analysis")
    risk_assessment: str = Field(description="Overall risk assessment")
    recommendations: list[str] = Field(description="Follow-up recommendations")


SYSTEM_DETECT_ANOMALIES = """\
You are an expert network security analyst \
detecting anomalous traffic patterns.

Given network flow data, identify:
1. Anomaly type (lateral_movement, c2_beacon, \
data_exfiltration, dns_tunneling, port_scan, \
protocol_anomaly, bandwidth_spike, beaconing)
2. Severity (critical, high, medium, low)
3. Confidence score (0.0-1.0)
4. Relevant MITRE ATT&CK tactic

Consider flow patterns, timing, volume, \
protocol misuse, and known threat signatures."""


SYSTEM_CLASSIFY_THREATS = """\
You are an expert threat analyst classifying \
network-based threats from anomaly detections.

Given the detected anomalies, determine:
1. Threat name and category
2. Kill chain phase (recon, weaponize, deliver, \
exploit, install, c2, actions)
3. Severity and confidence
4. Recommended containment action

Correlate across multiple anomalies to identify \
coordinated attack campaigns."""


SYSTEM_ANALYZE_PROTOCOLS = """\
You are an expert network protocol analyst \
evaluating protocol-level behavior.

Given protocol flow statistics, assess:
1. Protocol-specific anomalies
2. Misuse patterns (e.g. DNS tunneling, HTTP C2)
3. Risk level for each protocol
4. Recommendations for hardening

Focus on deviations from normal baselines."""


SYSTEM_REPORT = """\
You are an expert network security analyst \
generating a traffic analysis summary.

Given all detected anomalies, classified threats, \
and protocol analyses, produce:
1. Concise executive summary
2. Key findings with evidence
3. Overall risk assessment
4. Prioritized recommendations

Be direct and actionable."""
