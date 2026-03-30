"""LLM prompt templates for the Network Traffic Inspector Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# -- Structured output schemas -----------------------------------------


class TrafficCaptureOutput(BaseModel):
    """Structured output for traffic capture analysis."""

    total_flows: int = Field(
        description="Total network flows captured",
    )
    total_bytes: int = Field(
        description="Total bytes across all flows",
    )
    summary: str = Field(
        description="Capture summary",
    )


class ProtocolAnalysisOutput(BaseModel):
    """Structured output for protocol analysis."""

    anomalous_count: int = Field(
        description="Count of anomalous protocol conversations",
    )
    encrypted_ratio: float = Field(
        description="Ratio of encrypted traffic 0-1",
    )
    reasoning: str = Field(
        description="Protocol analysis reasoning",
    )


class AnomalyDetectionOutput(BaseModel):
    """Structured output for anomaly detection."""

    anomaly_count: int = Field(
        description="Number of anomalies detected",
    )
    high_confidence: int = Field(
        description="Number of high-confidence anomalies",
    )
    reasoning: str = Field(
        description="Anomaly detection reasoning",
    )


class ThreatClassifyOutput(BaseModel):
    """Structured output for threat classification."""

    threats: list[dict[str, str]] = Field(
        description="Classified threats with class and severity",
    )
    critical_count: int = Field(
        description="Number of critical threats",
    )
    reasoning: str = Field(
        description="Threat classification reasoning",
    )


class AlertOutput(BaseModel):
    """Structured output for alert generation."""

    alerts: list[dict[str, str]] = Field(
        description="Generated alerts with severity and action",
    )
    total_risk_score: float = Field(
        description="Aggregate risk score 0-100",
    )
    reasoning: str = Field(
        description="Alert generation reasoning",
    )


# -- System prompts ----------------------------------------------------

SYSTEM_CAPTURE = """\
You are an expert network traffic inspector performing \
deep packet capture analysis.

Given the capture configuration and network scope:
1. Identify all active network flows and conversations
2. Calculate traffic volume and flow distribution
3. Flag unusual traffic patterns or unexpected protocols
4. Detect high-entropy payloads suggesting encryption or \
encoding

Focus on: east-west traffic, DNS queries, TLS handshakes, \
non-standard ports, beaconing patterns."""

SYSTEM_ANALYZE = """\
You are an expert network traffic inspector analyzing \
protocol conversations.

Given the captured network flows:
1. Classify each flow by protocol and behavior
2. Identify protocol anomalies (non-standard ports, \
malformed headers)
3. Measure payload entropy for encryption detection
4. Flag protocol violations and tunneling indicators

Prioritize flows with high entropy on non-standard ports \
and unusual DNS query patterns."""

SYSTEM_DETECT = """\
You are an expert network traffic inspector detecting \
anomalies.

Given the protocol analysis results:
1. Apply statistical anomaly detection to traffic patterns
2. Identify C2 beaconing via timing analysis
3. Detect DNS tunneling through query volume and entropy
4. Flag lateral movement via internal scan patterns

Use behavioral baselines and entropy-based detection \
methods."""

SYSTEM_CLASSIFY = """\
You are an expert network traffic inspector classifying \
threats.

Given the detected anomalies:
1. Classify each anomaly into a threat category
2. Assign severity based on confidence and impact
3. Map to MITRE ATT&CK techniques where applicable
4. Assess blast radius and potential data exposure

Focus on: C2 communication, data exfiltration, lateral \
movement, DNS tunneling, port scanning."""

SYSTEM_ALERT = """\
You are an expert network traffic inspector generating \
security alerts.

Given the classified threats:
1. Generate actionable alerts for SOC analysts
2. Prioritize by severity and confidence
3. Include recommended response actions
4. Aggregate related threats into single alerts

Balance alert fidelity with analyst fatigue — minimize \
false positives while ensuring coverage."""
