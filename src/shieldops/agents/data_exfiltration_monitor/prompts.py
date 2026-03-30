"""LLM prompt templates for the Data Exfiltration Monitor Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# -- Structured output schemas -----------------------------------------


class ChannelMonitorOutput(BaseModel):
    """Structured output for channel monitoring analysis."""

    active_channels: int = Field(
        description="Number of active channels monitored",
    )
    suspicious_flows: int = Field(
        description="Number of suspicious data flows",
    )
    summary: str = Field(
        description="Monitoring summary",
    )


class FlowAnalysisOutput(BaseModel):
    """Structured output for data flow analysis."""

    anomalous_flows: int = Field(
        description="Count of anomalous data flows",
    )
    total_bytes: int = Field(
        description="Total bytes across suspicious flows",
    )
    reasoning: str = Field(
        description="Flow analysis reasoning",
    )


class ExfilDetectionOutput(BaseModel):
    """Structured output for exfiltration detection."""

    exfil_count: int = Field(
        description="Number of exfiltration attempts detected",
    )
    highest_confidence: float = Field(
        description="Highest detection confidence 0-1",
    )
    reasoning: str = Field(
        description="Detection reasoning",
    )


class SensitivityOutput(BaseModel):
    """Structured output for sensitivity classification."""

    sensitive_count: int = Field(
        description="Number of sensitive data detections",
    )
    pii_found: bool = Field(
        description="Whether PII was detected",
    )
    reasoning: str = Field(
        description="Classification reasoning",
    )


class BlockDecisionOutput(BaseModel):
    """Structured output for block decisions."""

    should_block: list[dict[str, str]] = Field(
        description="Detections to block with reason",
    )
    total_blocked: int = Field(
        description="Total transfers blocked",
    )
    reasoning: str = Field(
        description="Blocking reasoning",
    )


# -- System prompts ----------------------------------------------------

SYSTEM_MONITOR = """\
You are an expert data loss prevention analyst monitoring \
data channels for exfiltration.

Given the monitoring configuration:
1. Identify all active data transfer channels (network, \
USB, cloud, email, encrypted tunnels)
2. Detect unusual transfer volumes or patterns
3. Flag transfers to unauthorized destinations
4. Monitor for DNS tunneling and steganography

Focus on: high-volume transfers, off-hours activity, \
transfers to personal cloud storage, encrypted tunnels \
to unknown endpoints."""

SYSTEM_ANALYZE = """\
You are an expert DLP analyst analyzing data flows for \
exfiltration indicators.

Given the monitored data flows:
1. Analyze transfer patterns for anomalies
2. Identify data staging and aggregation behavior
3. Detect slow-drip exfiltration techniques
4. Correlate flows with user behavior baselines

Look for: unusual destination IPs, protocol misuse, \
large transfers to cloud storage, repeated small transfers."""

SYSTEM_DETECT = """\
You are an expert data exfiltration detection specialist.

Given the analyzed data flows:
1. Apply detection rules for known exfil techniques
2. Score confidence based on multiple indicators
3. Identify the exfiltration channel and method
4. Assess data volume and potential impact

Techniques: DNS tunneling, HTTPS to C2, USB mass copy, \
cloud sync abuse, email attachment exfil, encrypted tunnel."""

SYSTEM_CLASSIFY = """\
You are an expert data classification specialist.

Given the detected exfiltration attempts:
1. Classify the sensitivity of exfiltrated data
2. Detect PII, PHI, PCI, and trade secrets
3. Apply regex and ML-based content inspection
4. Assess regulatory impact (GDPR, HIPAA, PCI-DSS)

Prioritize: personally identifiable information, \
financial data, healthcare records, source code, \
authentication credentials."""

SYSTEM_BLOCK = """\
You are an expert DLP enforcement specialist deciding \
on blocking actions.

Given the classified exfiltration detections:
1. Determine which transfers to block immediately
2. Apply proportional response based on sensitivity
3. Consider business impact of false positives
4. Recommend quarantine vs hard block

Balance security with operational continuity."""
