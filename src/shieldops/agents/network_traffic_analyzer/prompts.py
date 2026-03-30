"""Network Traffic Analyzer Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class PatternAnalysisOutput(BaseModel):
    """LLM output for traffic pattern analysis."""

    summary: str = Field(
        description="Brief summary of traffic patterns",
    )
    risk_level: str = Field(
        description="Risk level: critical, high, medium, low",
    )
    suspicious_patterns: list[str] = Field(
        description="Identified suspicious traffic patterns",
    )
    recommendations: list[str] = Field(
        description="Recommendations for further investigation",
    )


class AnomalyDetectionOutput(BaseModel):
    """LLM output for anomaly detection."""

    threat_type: str = Field(
        description=(
            "Type: lateral_movement, data_exfiltration, "
            "c2_communication, port_scan, "
            "dns_tunneling, brute_force"
        ),
    )
    severity: str = Field(
        description="Severity: critical, high, medium, low",
    )
    confidence: float = Field(
        description="Confidence score 0.0-1.0",
    )
    description: str = Field(
        description="Detailed description of the anomaly",
    )
    mitre_tactic: str = Field(
        description="MITRE ATT&CK tactic ID",
    )


class ThreatClassificationOutput(BaseModel):
    """LLM output for threat classification."""

    threat_name: str = Field(
        description="Name of the identified threat",
    )
    severity: str = Field(
        description="Severity: critical, high, medium, low",
    )
    confidence: float = Field(
        description="Confidence score 0.0-1.0",
    )
    kill_chain_phase: str = Field(
        description=("Kill chain phase: recon, weaponize, deliver, exploit, install, c2, actions"),
    )
    recommended_action: str = Field(
        description="Recommended containment action",
    )
    reasoning: str = Field(
        description="Detailed reasoning for classification",
    )


class PolicyEnforcementOutput(BaseModel):
    """LLM output for policy enforcement decisions."""

    action: str = Field(
        description="Enforcement action to take",
    )
    priority: str = Field(
        description="Priority: immediate, high, medium, low",
    )
    justification: str = Field(
        description="Justification for the action",
    )
    blast_radius: str = Field(
        description="Estimated blast radius of enforcement",
    )


class ReportOutput(BaseModel):
    """LLM output for traffic analysis report."""

    executive_summary: str = Field(
        description="One-paragraph executive summary",
    )
    key_findings: list[str] = Field(
        description="Top findings from the analysis",
    )
    risk_assessment: str = Field(
        description="Overall risk assessment",
    )
    recommendations: list[str] = Field(
        description="Prioritized follow-up recommendations",
    )


SYSTEM_ANALYZE_PATTERNS = (
    "You are an expert network security analyst "
    "analyzing traffic flow patterns.\n"
    "Given network flow data, identify:\n"
    "1. Unusual communication patterns between "
    "hosts\n"
    "2. Volume anomalies — spikes or sustained "
    "high-bandwidth transfers\n"
    "3. Protocol misuse — non-standard port usage "
    "or protocol violations\n"
    "4. Timing anomalies — beaconing intervals or "
    "off-hours activity\n"
    "5. Provide risk level and recommendations"
)

SYSTEM_DETECT_ANOMALIES = (
    "You are an expert network threat analyst "
    "detecting anomalous traffic patterns.\n"
    "Given traffic patterns, identify:\n"
    "1. Threat type: lateral_movement, "
    "data_exfiltration, c2_communication, "
    "port_scan, dns_tunneling, brute_force\n"
    "2. Severity: critical, high, medium, low\n"
    "3. Confidence score 0.0-1.0\n"
    "4. Relevant MITRE ATT&CK tactic\n"
    "Consider flow volumes, timing, protocol "
    "misuse, and known threat signatures."
)

SYSTEM_CLASSIFY_THREATS = (
    "You are an expert threat analyst classifying "
    "network-based threats from anomaly data.\n"
    "Given the detected anomalies, determine:\n"
    "1. Threat name and category\n"
    "2. Kill chain phase: recon, weaponize, "
    "deliver, exploit, install, c2, actions\n"
    "3. Severity and confidence\n"
    "4. Recommended containment action\n"
    "Correlate across multiple anomalies to "
    "identify coordinated campaigns."
)

SYSTEM_ENFORCE_POLICIES = (
    "You are a network security policy analyst "
    "determining enforcement actions.\n"
    "Given classified threats, recommend:\n"
    "1. Specific enforcement action (block, "
    "isolate, rate-limit, alert)\n"
    "2. Priority level for the action\n"
    "3. Justification with evidence\n"
    "4. Estimated blast radius of enforcement\n"
    "Minimize false-positive impact while "
    "containing confirmed threats."
)

SYSTEM_REPORT = (
    "You are an expert network security analyst "
    "generating a traffic analysis report.\n"
    "Given all detected anomalies, classified "
    "threats, and policy enforcements:\n"
    "1. Concise executive summary\n"
    "2. Key findings with evidence\n"
    "3. Overall risk assessment\n"
    "4. Prioritized recommendations\n"
    "Be direct and actionable."
)
