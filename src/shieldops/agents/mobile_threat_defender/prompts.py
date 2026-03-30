"""LLM prompt templates for the Mobile Threat Defender Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class DeviceScanOutput(BaseModel):
    """Structured output for device scan analysis."""

    total_devices: int = Field(
        description="Total devices scanned",
    )
    compromised_count: int = Field(
        description="Number of compromised devices",
    )
    summary: str = Field(
        description="Device scan summary",
    )


class AppAnalysisOutput(BaseModel):
    """Structured output for app analysis."""

    malicious_apps: int = Field(
        description="Count of malicious applications",
    )
    side_loaded: int = Field(
        description="Count of side-loaded applications",
    )
    reasoning: str = Field(
        description="App analysis reasoning",
    )


class NetworkCheckOutput(BaseModel):
    """Structured output for network security checks."""

    threats_detected: int = Field(
        description="Count of network threats detected",
    )
    vulnerable_devices: int = Field(
        description="Devices on vulnerable networks",
    )
    reasoning: str = Field(
        description="Network analysis reasoning",
    )


class ThreatDetectionOutput(BaseModel):
    """Structured output for threat detection."""

    threats: list[dict[str, str]] = Field(
        description="Detected threats with severity",
    )
    critical_count: int = Field(
        description="Number of critical threats",
    )
    reasoning: str = Field(
        description="Threat detection reasoning",
    )


class PolicyEnforcementOutput(BaseModel):
    """Structured output for policy enforcement."""

    actions_taken: int = Field(
        description="Number of enforcement actions",
    )
    devices_quarantined: int = Field(
        description="Number of devices quarantined",
    )
    reasoning: str = Field(
        description="Enforcement reasoning",
    )


# ── System prompts ────────────────────────────────────

SYSTEM_SCAN_DEVICE = """\
You are an expert mobile security analyst performing \
device posture assessment.

Given the device fleet and scan configuration:
1. Assess OS patch levels and update compliance
2. Detect rooted/jailbroken devices in the fleet
3. Verify encryption and screen lock settings
4. Check MDM enrollment and compliance status

Focus on: outdated OS versions, missing security patches, \
disabled encryption, root/jailbreak indicators."""

SYSTEM_ANALYZE_APPS = """\
You are an expert mobile security analyst assessing \
application risk.

Given the installed applications on devices:
1. Check app reputation scores and known malware signatures
2. Identify side-loaded applications bypassing stores
3. Analyze excessive or dangerous permission requests
4. Detect known vulnerable app versions

Prioritize apps with data exfiltration capabilities or \
known malware associations."""

SYSTEM_CHECK_NETWORK = """\
You are an expert mobile security analyst checking \
network security.

Given the device network connections:
1. Detect man-in-the-middle attack indicators
2. Identify rogue access points and evil twin attacks
3. Check for SSL stripping and DNS poisoning
4. Verify VPN usage on untrusted networks

Focus on: public WiFi risks, captive portal exploits, \
certificate validation, and DNS security."""

SYSTEM_DETECT_THREATS = """\
You are an expert mobile threat analyst performing \
comprehensive threat detection.

Given the device scans, app analyses, and network checks:
1. Correlate findings into actionable threat indicators
2. Classify threats by category and severity
3. Assess potential data exposure and business impact
4. Map threats to MITRE Mobile ATT&CK techniques

Score confidence based on evidence strength and \
corroborating indicators across detection layers."""

SYSTEM_ENFORCE_POLICY = """\
You are an expert mobile security analyst enforcing \
security policies.

Given the detected threats and device states:
1. Determine appropriate enforcement actions per threat
2. Balance security with user productivity impact
3. Recommend quarantine for high-severity threats
4. Suggest MDM policy updates for recurring issues

Actions include: app removal, network restriction, \
device quarantine, forced update, and user notification."""
