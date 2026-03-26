"""IoT/OT Security Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class DeviceDiscoveryResult(BaseModel):
    """Structured output from LLM-assisted device classification."""

    summary: str = Field(
        description="Brief summary of discovered devices",
    )
    unmanaged_count: int = Field(
        description="Number of unmanaged devices found",
    )
    ai_connected_count: int = Field(
        description="Devices connected to AI/ML pipelines",
    )
    risk_level: str = Field(
        description="Overall risk: low, medium, high, critical",
    )
    recommended_actions: list[str] = Field(
        description="Priority actions for discovered devices",
    )


class BehaviorAnalysisResult(BaseModel):
    """Structured output from LLM-assisted behavior analysis."""

    summary: str = Field(
        description="Brief summary of behavioral analysis",
    )
    anomalous_devices: int = Field(
        description="Count of devices with anomalous behavior",
    )
    threat_level: str = Field(
        description="Threat level: none, low, medium, high, critical",
    )
    attack_indicators: list[str] = Field(
        description="Indicators of attack or compromise",
    )
    immediate_actions: list[str] = Field(
        description="Actions to take immediately",
    )


class VulnerabilityAssessmentResult(BaseModel):
    """Structured output from LLM-assisted vuln assessment."""

    summary: str = Field(
        description="Brief summary of vulnerability assessment",
    )
    critical_count: int = Field(
        description="Number of critical vulnerabilities",
    )
    unpatched_devices: int = Field(
        description="Devices with no available patches",
    )
    segmentation_gaps: list[str] = Field(
        description="Network segmentation gaps found",
    )
    hardening_recommendations: list[str] = Field(
        description="Device hardening recommendations",
    )


SYSTEM_DEVICE_DISCOVERY = (
    "You are an IoT/OT security specialist analyzing "
    "discovered devices on an enterprise network.\n"
    "Given the discovery results:\n"
    "1. Classify devices by risk based on category, "
    "firmware age, and management status\n"
    "2. Identify unmanaged or shadow IoT devices\n"
    "3. Flag AI-connected devices (edge AI, ML sensors) "
    "as high-priority attack surfaces\n"
    "4. Identify devices using insecure protocols "
    "(Telnet, FTP, Modbus without auth)\n"
    "5. Recommend immediate isolation for critical-risk "
    "unmanaged devices"
)

SYSTEM_BEHAVIOR_ANALYSIS = (
    "You are an IoT/OT behavioral security analyst.\n"
    "Given device behavioral profiles and detected "
    "anomalies:\n"
    "1. Correlate anomalies to identify coordinated "
    "attacks on IoT/OT networks\n"
    "2. Detect data exfiltration from AI-connected "
    "devices (model theft, training data leaks)\n"
    "3. Identify protocol anomalies (unexpected Modbus, "
    "BACnet, or MQTT traffic)\n"
    "4. Assess lateral movement risk from IoT to IT "
    "and OT networks\n"
    "5. Map threats to ICS-CERT advisories and MITRE "
    "ATT&CK for ICS"
)

SYSTEM_VULNERABILITY_ASSESSMENT = (
    "You are an IoT/OT vulnerability researcher.\n"
    "Given the vulnerability assessment results:\n"
    "1. Prioritize by exploitability and blast radius "
    "in OT environments\n"
    "2. Identify firmware vulnerabilities with no patch "
    "available (compensating controls needed)\n"
    "3. Flag devices that cannot be patched without "
    "production downtime\n"
    "4. Recommend micro-segmentation policies for "
    "vulnerable devices\n"
    "5. Assess risk of AI model poisoning via "
    "compromised edge sensors"
)
