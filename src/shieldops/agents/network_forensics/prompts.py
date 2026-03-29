"""Network Forensics Agent — LLM prompt templates and output schemas."""

from pydantic import BaseModel, Field


class SessionAnalysisOutput(BaseModel):
    """LLM output for session reconstruction analysis."""

    summary: str = Field(description="Brief summary of session reconstruction findings")
    suspicious_count: int = Field(description="Number of suspicious sessions identified")
    protocols_of_interest: list[str] = Field(
        description="Protocols warranting deeper investigation"
    )
    anomalies: list[str] = Field(description="Session anomalies detected")


class TimelineOutput(BaseModel):
    """LLM output for timeline analysis."""

    summary: str = Field(description="Brief timeline analysis summary")
    attack_phases: list[str] = Field(description="Identified attack phases in chronological order")
    key_events: list[str] = Field(description="Most significant events in the timeline")
    time_span_description: str = Field(
        description="Human-readable description of the attack timespan"
    )


class LateralMovementOutput(BaseModel):
    """LLM output for lateral movement tracing."""

    summary: str = Field(description="Lateral movement analysis summary")
    hop_count: int = Field(description="Number of lateral movement hops detected")
    techniques_used: list[str] = Field(description="Lateral movement techniques observed")
    compromised_hosts: list[str] = Field(description="Hosts confirmed or likely compromised")
    mitre_techniques: list[str] = Field(description="MITRE ATT&CK technique IDs")
    risk_level: str = Field(description="Risk level: critical, high, medium, low")


class ExfiltrationOutput(BaseModel):
    """LLM output for exfiltration path mapping."""

    summary: str = Field(description="Exfiltration analysis summary")
    exfil_methods: list[str] = Field(description="Exfiltration methods detected")
    total_bytes_estimate: int = Field(description="Estimated total bytes exfiltrated")
    destinations: list[str] = Field(description="Exfiltration destination IPs/domains")
    encoding_methods: list[str] = Field(description="Data encoding methods used")
    confidence: float = Field(description="Confidence in exfiltration detection 0-1")
    mitre_techniques: list[str] = Field(description="MITRE ATT&CK technique IDs")


SYSTEM_SESSION_ANALYSIS = (
    "You are a network forensics analyst reconstructing "
    "network sessions from captured traffic.\n"
    "Given the following session data:\n"
    "1. Identify suspicious sessions by anomalous "
    "byte ratios, unusual ports, or beaconing patterns\n"
    "2. Flag encrypted sessions to unknown destinations "
    "or self-signed certificates\n"
    "3. Detect DNS tunneling, HTTP C2 beacons, and "
    "covert channel indicators\n"
    "4. Note protocols of interest for deeper packet "
    "inspection\n"
    "5. Summarize session patterns that suggest "
    "compromise or data theft"
)

SYSTEM_TIMELINE_ANALYSIS = (
    "You are a forensic investigator building an "
    "attack timeline from network evidence.\n"
    "Given the following timeline events:\n"
    "1. Identify initial access — first suspicious "
    "connection or exploit attempt\n"
    "2. Map reconnaissance phases — port scans, DNS "
    "enumeration, service probing\n"
    "3. Trace execution phases — payload delivery, "
    "C2 establishment, tool deployment\n"
    "4. Identify persistence — beaconing intervals, "
    "scheduled callbacks, DNS keepalives\n"
    "5. Sequence events into a coherent attack "
    "narrative with timestamps"
)

SYSTEM_LATERAL_MOVEMENT = (
    "You are a threat hunter analyzing lateral "
    "movement in network forensic evidence.\n"
    "Given the following network sessions:\n"
    "1. Trace SMB/RDP/SSH/WinRM connections between "
    "internal hosts that indicate pivoting\n"
    "2. Identify credential reuse — same auth tokens "
    "or hashes across multiple hosts\n"
    "3. Detect pass-the-hash, pass-the-ticket, or "
    "Kerberoasting artifacts\n"
    "4. Map the movement graph — source to destination "
    "hops with timestamps\n"
    "5. Correlate with MITRE ATT&CK lateral movement "
    "techniques (T1021, T1550, T1558)"
)

SYSTEM_EXFILTRATION = (
    "You are a data exfiltration analyst examining "
    "network traffic for data theft indicators.\n"
    "Given the following network evidence:\n"
    "1. Identify large outbound data transfers to "
    "external IPs, especially outside business hours\n"
    "2. Detect DNS exfiltration — encoded data in "
    "DNS queries, high query volumes to single domains\n"
    "3. Flag HTTP/HTTPS uploads — large POST bodies, "
    "cloud storage uploads, paste sites\n"
    "4. Identify encrypted channels to unknown "
    "destinations — custom TLS, Tor, VPN tunnels\n"
    "5. Calculate total estimated exfiltration volume "
    "and map exfil paths with confidence scores"
)
