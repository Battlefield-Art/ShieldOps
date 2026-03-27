"""Backup Security Posture Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class InventoryInsight(BaseModel):
    """Structured output from backup inventory."""

    summary: str = Field(description="Backup inventory overview")
    unprotected_assets: list[str] = Field(description="Assets without backup coverage")
    capacity_risks: list[str] = Field(description="Backup capacity concerns")


class ConfigInsight(BaseModel):
    """Structured output from config assessment."""

    summary: str = Field(description="Security config overview")
    config_gaps: list[str] = Field(description="Critical config gaps")
    ransomware_risks: list[str] = Field(description="Ransomware vulnerability points")


class VulnInsight(BaseModel):
    """Structured output from vulnerability scan."""

    summary: str = Field(description="Vulnerability assessment overview")
    critical_vulns: list[str] = Field(description="Critical vulnerabilities to fix")
    attack_vectors: list[str] = Field(description="Exploitable attack vectors")


class RecoveryInsight(BaseModel):
    """Structured output from recovery testing."""

    summary: str = Field(description="Recovery test results overview")
    failed_tests: list[str] = Field(description="Failed recovery tests")
    rpo_rto_gaps: list[str] = Field(description="RPO/RTO objective gaps")


SYSTEM_INVENTORY = (
    "You are a backup infrastructure analyst "
    "inventorying backup assets.\n"
    "1. Identify assets without backup coverage\n"
    "2. Flag backup stores nearing capacity\n"
    "3. Detect stale or failed backups\n"
    "4. Assess immutability coverage"
)

SYSTEM_CONFIG = (
    "You are a backup security analyst assessing "
    "configuration security.\n"
    "1. Evaluate encryption at rest and in transit\n"
    "2. Check MFA and access control settings\n"
    "3. Assess air-gapping and immutability\n"
    "4. Identify ransomware attack surface"
)

SYSTEM_VULN = (
    "You are a vulnerability analyst scanning "
    "backup infrastructure.\n"
    "1. Identify exploitable vulnerabilities\n"
    "2. Assess ransomware risk per component\n"
    "3. Map CVEs to backup systems\n"
    "4. Evaluate blast radius of each finding"
)

SYSTEM_RECOVERY = (
    "You are a disaster recovery analyst testing "
    "backup recovery capabilities.\n"
    "1. Evaluate recovery time against RTO\n"
    "2. Verify data integrity post-recovery\n"
    "3. Test failover procedures\n"
    "4. Identify recovery capability gaps"
)
