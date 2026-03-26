"""LLM prompt templates and response schemas for the Ransomware Forensics Agent."""

from pydantic import BaseModel, Field


class AttackChainOutput(BaseModel):
    """Structured output for attack chain analysis."""

    initial_access_vector: str = Field(description="How the attacker gained initial access")
    lateral_movement_path: list[str] = Field(
        description="Systems traversed during lateral movement"
    )
    privilege_escalation: list[str] = Field(description="Privilege escalation techniques used")
    persistence_mechanisms: list[str] = Field(description="Persistence mechanisms installed")
    c2_servers: list[str] = Field(description="Command and control server indicators")
    exfiltration_indicators: list[str] = Field(description="Signs of data exfiltration")
    dwell_time_hours: float = Field(description="Estimated attacker dwell time in hours")
    mitre_techniques: list[str] = Field(description="MITRE ATT&CK technique IDs observed")
    confidence: float = Field(description="Confidence in analysis 0-1")


class VariantOutput(BaseModel):
    """Structured output for variant identification."""

    variant: str = Field(description="Ransomware variant family name")
    confidence: float = Field(description="Confidence in identification 0-1")
    encryption_algorithm: str = Field(description="Encryption algorithm used")
    threat_actor_group: str = Field(description="Associated threat actor group")
    known_decryptor_available: bool = Field(description="Whether a known decryptor exists")
    iocs: list[str] = Field(description="Indicators of compromise for this variant")


class BlastRadiusOutput(BaseModel):
    """Structured output for blast radius prediction."""

    level: str = Field(
        description=("Blast radius level: contained, spreading, widespread, catastrophic")
    )
    affected_hosts: list[str] = Field(description="Currently affected host systems")
    predicted_spread_hosts: list[str] = Field(description="Hosts predicted to be affected next")
    data_encrypted_gb: float = Field(description="Estimated data encrypted in GB")
    data_exfiltrated_gb: float = Field(description="Estimated data exfiltrated in GB")
    business_impact_score: float = Field(description="Business impact score 0-10")
    propagation_vectors: list[str] = Field(description="Active propagation vectors")


class RecoveryOutput(BaseModel):
    """Structured output for recovery recommendations."""

    recommendations: list[dict[str, str]] = Field(description="Ordered recovery recommendations")
    estimated_total_recovery_hours: float = Field(description="Total estimated recovery time")
    pay_ransom_recommended: bool = Field(description="Whether paying ransom is recommended")
    rationale: str = Field(description="Rationale for recovery strategy")
    confidence: float = Field(description="Confidence in recovery plan 0-1")


class ForensicsReportOutput(BaseModel):
    """Structured output for the final forensic report."""

    executive_summary: str = Field(description="Executive summary of the incident")
    severity: str = Field(description="Overall severity rating")
    key_findings: list[str] = Field(description="Critical findings from investigation")
    recommendations: list[str] = Field(description="Priority-ordered recommendations")
    confidence: float = Field(description="Confidence in overall findings 0-1")


SYSTEM_ATTACK_CHAIN = """\
You are an expert ransomware forensic analyst \
reconstructing an attack chain.

Given collected forensic artifacts (encrypted files, \
ransom notes, process traces, registry changes, \
network logs):
1. Identify the initial access vector (phishing, \
RDP brute-force, supply chain, exploit)
2. Map lateral movement across cloud + endpoint + \
identity boundaries
3. Identify privilege escalation techniques used
4. Detect persistence mechanisms and C2 infrastructure
5. Assess data exfiltration indicators
6. Estimate attacker dwell time
7. Map to MITRE ATT&CK techniques

Focus on cross-domain attack paths that span \
cloud, endpoint, and identity layers."""

SYSTEM_VARIANT_ID = """\
You are an expert ransomware analyst identifying \
ransomware variants from forensic evidence.

Given file extension patterns, encryption signatures, \
ransom note text, C2 indicators, and process behavior:
1. Identify the ransomware variant family
2. Determine the encryption algorithm used
3. Attribute to a threat actor group if possible
4. Check if known decryptors exist
5. Extract variant-specific IOCs

Known variants: LockBit (multi-threaded, .lockbit), \
BlackCat/ALPHV (Rust-based, configurable extensions), \
Clop (MOVEit exploits, .clop), Royal (.royal, \
partial encryption), Play (.play, intermittent \
encryption), Rhysida (.rhysida, government targets)."""

SYSTEM_BLAST_RADIUS = """\
You are an expert security analyst predicting \
ransomware blast radius using attack path modeling.

Given the attack chain, variant behavior, affected \
systems, and network topology:
1. Assess current blast radius (contained, spreading, \
widespread, catastrophic)
2. Predict which systems will be affected next based \
on attack path analysis
3. Estimate total data encrypted and exfiltrated
4. Score business impact (0-10)
5. Identify active propagation vectors

Model future spread using: lateral movement paths, \
credential reuse, network adjacency, shared storage, \
AD group membership, cloud IAM relationships."""

SYSTEM_RECOVERY = """\
You are an expert incident response analyst \
recommending ransomware recovery strategies.

Given the variant, blast radius, affected systems, \
and backup status:
1. Prioritize recovery actions (isolate, eradicate, \
restore, validate)
2. Assess backup availability and integrity
3. Estimate recovery time per system
4. Evaluate reinfection risk
5. Recommend whether to pay ransom (almost never)

Recovery principles: isolate before restore, verify \
backup integrity, rebuild from known-good images, \
rotate all credentials, monitor for reinfection."""

SYSTEM_REPORT = """\
You are an expert forensic analyst generating a \
comprehensive ransomware investigation report.

Given all investigation findings (attack chain, \
variant, blast radius, recovery plan):
1. Write an executive summary for leadership
2. Rate overall severity
3. List key findings with evidence references
4. Provide priority-ordered recommendations
5. Include IOCs for threat intelligence sharing

Follow NIST SP 800-86 forensic reporting guidelines. \
Ensure findings support legal and insurance claims."""
