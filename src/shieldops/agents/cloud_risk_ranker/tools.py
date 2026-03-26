"""Cloud Risk Ranker Agent — Tool functions for risk ranking."""

from __future__ import annotations

import hashlib
import random
import uuid
from typing import Any

import structlog

from .models import (
    AttackerTactic,
    AttackPath,
    CloudFinding,
    ExploitabilityAssessment,
    ExploitabilityLevel,
    RemediationPriority,
    RiskCategory,
)

logger = structlog.get_logger()

# ---------------------------------------------------------------
# MITRE ATT&CK mapping per risk category
# ---------------------------------------------------------------
_TACTIC_MAP: dict[str, list[dict[str, str]]] = {
    "misconfiguration": [
        {
            "tactic_id": "TA0001",
            "tactic_name": "Initial Access",
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing App",
            "procedure": (
                "Attacker exploits misconfigured public endpoint to gain initial foothold"
            ),
        },
        {
            "tactic_id": "TA0004",
            "tactic_name": "Privilege Escalation",
            "technique_id": "T1078.004",
            "technique_name": "Cloud Accounts",
            "procedure": ("Misconfigured IAM allows escalation to admin privileges"),
        },
    ],
    "vulnerability": [
        {
            "tactic_id": "TA0001",
            "tactic_name": "Initial Access",
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing App",
            "procedure": ("CVE exploitation for remote code execution on cloud workloads"),
        },
        {
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "technique_id": "T1059.004",
            "technique_name": "Unix Shell",
            "procedure": ("Post-exploit shell execution on vulnerable container or VM"),
        },
    ],
    "identity_exposure": [
        {
            "tactic_id": "TA0006",
            "tactic_name": "Credential Access",
            "technique_id": "T1528",
            "technique_name": "Steal App Access Token",
            "procedure": (
                "Exposed service account keys allow credential theft and lateral movement"
            ),
        },
        {
            "tactic_id": "TA0008",
            "tactic_name": "Lateral Movement",
            "technique_id": "T1550.001",
            "technique_name": "App Access Token",
            "procedure": ("Stolen cloud tokens enable cross-service lateral movement"),
        },
    ],
    "data_exposure": [
        {
            "tactic_id": "TA0009",
            "tactic_name": "Collection",
            "technique_id": "T1530",
            "technique_name": "Data from Cloud Storage",
            "procedure": ("Public storage buckets allow bulk data exfiltration"),
        },
        {
            "tactic_id": "TA0010",
            "tactic_name": "Exfiltration",
            "technique_id": "T1567",
            "technique_name": "Exfil Over Web Service",
            "procedure": ("Data exfiltrated via cloud storage APIs to attacker-controlled account"),
        },
    ],
    "network_exposure": [
        {
            "tactic_id": "TA0001",
            "tactic_name": "Initial Access",
            "technique_id": "T1133",
            "technique_name": "External Remote Services",
            "procedure": ("Open network ports expose admin interfaces to the internet"),
        },
        {
            "tactic_id": "TA0011",
            "tactic_name": "Command and Control",
            "technique_id": "T1071.001",
            "technique_name": "Web Protocols",
            "procedure": ("Unrestricted egress allows C2 communication over HTTPS"),
        },
    ],
}

# ---------------------------------------------------------------
# Simulated finding templates per cloud provider
# ---------------------------------------------------------------
_FINDING_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "aws": [
        {
            "resource_type": "s3_bucket",
            "category": RiskCategory.DATA_EXPOSURE,
            "title": "S3 bucket publicly accessible",
            "severity": "critical",
        },
        {
            "resource_type": "ec2_instance",
            "category": RiskCategory.VULNERABILITY,
            "title": "EC2 instance running unpatched AMI",
            "severity": "high",
            "cve_id": "CVE-2024-21626",
        },
        {
            "resource_type": "iam_role",
            "category": RiskCategory.IDENTITY_EXPOSURE,
            "title": "IAM role with wildcard permissions",
            "severity": "critical",
        },
        {
            "resource_type": "security_group",
            "category": RiskCategory.NETWORK_EXPOSURE,
            "title": "Security group allows 0.0.0.0/0 SSH",
            "severity": "high",
        },
        {
            "resource_type": "rds_instance",
            "category": RiskCategory.MISCONFIGURATION,
            "title": "RDS instance without encryption",
            "severity": "high",
        },
    ],
    "gcp": [
        {
            "resource_type": "gcs_bucket",
            "category": RiskCategory.DATA_EXPOSURE,
            "title": "GCS bucket with allUsers access",
            "severity": "critical",
        },
        {
            "resource_type": "service_account",
            "category": RiskCategory.IDENTITY_EXPOSURE,
            "title": "Service account key older than 90 days",
            "severity": "high",
        },
        {
            "resource_type": "gce_instance",
            "category": RiskCategory.VULNERABILITY,
            "title": "GCE instance with known CVE",
            "severity": "high",
            "cve_id": "CVE-2024-3094",
        },
        {
            "resource_type": "firewall_rule",
            "category": RiskCategory.NETWORK_EXPOSURE,
            "title": "Firewall rule allows 0.0.0.0/0 ingress",
            "severity": "high",
        },
    ],
    "azure": [
        {
            "resource_type": "storage_account",
            "category": RiskCategory.DATA_EXPOSURE,
            "title": "Storage account with public blob access",
            "severity": "critical",
        },
        {
            "resource_type": "vm",
            "category": RiskCategory.VULNERABILITY,
            "title": "Azure VM with unpatched OS",
            "severity": "high",
            "cve_id": "CVE-2024-38063",
        },
        {
            "resource_type": "nsg",
            "category": RiskCategory.NETWORK_EXPOSURE,
            "title": "NSG allows RDP from any source",
            "severity": "critical",
        },
        {
            "resource_type": "aad_app",
            "category": RiskCategory.IDENTITY_EXPOSURE,
            "title": "App registration with excessive API perms",
            "severity": "high",
        },
    ],
    "kubernetes": [
        {
            "resource_type": "pod",
            "category": RiskCategory.MISCONFIGURATION,
            "title": "Pod running as root with host network",
            "severity": "critical",
        },
        {
            "resource_type": "cluster_role",
            "category": RiskCategory.IDENTITY_EXPOSURE,
            "title": "ClusterRole with wildcard verb binding",
            "severity": "critical",
        },
        {
            "resource_type": "container",
            "category": RiskCategory.VULNERABILITY,
            "title": "Container image with critical CVE",
            "severity": "high",
            "cve_id": "CVE-2024-21626",
        },
    ],
}

_REGIONS: dict[str, list[str]] = {
    "aws": ["us-east-1", "us-west-2", "eu-west-1"],
    "gcp": ["us-central1", "europe-west1", "asia-east1"],
    "azure": ["eastus", "westeurope", "southeastasia"],
    "kubernetes": ["default-cluster"],
}

_CAMPAIGNS: list[str] = [
    "SCATTERED SPIDER",
    "ALPHV/BlackCat",
    "LockBit 3.0",
    "APT29 / Cozy Bear",
    "APT28 / Fancy Bear",
    "Lazarus Group",
    "FIN7",
    "Volt Typhoon",
]


def _finding_hash(provider: str, rtype: str, idx: int) -> str:
    """Deterministic finding id."""
    raw = f"{provider}-{rtype}-{idx}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


class CloudRiskRankerToolkit:
    """Tools for multi-cloud risk ranking with ATT&CK correlation."""

    def __init__(
        self,
        cloud_clients: Any | None = None,
        threat_intel_client: Any | None = None,
    ) -> None:
        self._cloud_clients = cloud_clients
        self._threat_intel = threat_intel_client

    # ---------------------------------------------------------------
    # 1. Collect cloud findings
    # ---------------------------------------------------------------
    async def collect_findings(
        self,
        tenant_id: str,
        providers: list[str],
    ) -> list[CloudFinding]:
        """Collect security findings across cloud providers.

        Uses live cloud clients when available; otherwise
        returns simulated findings for demonstration.
        """
        logger.info(
            "cloud_risk_ranker.collect_findings",
            tenant_id=tenant_id,
            providers=providers,
        )

        if self._cloud_clients is not None:
            try:
                raw = await self._cloud_clients.get_findings(
                    tenant_id=tenant_id,
                    providers=providers,
                )
                return [CloudFinding(**f) for f in raw]
            except Exception:
                logger.exception("cloud_risk_ranker.collect.client_error")

        findings: list[CloudFinding] = []
        for prov in providers:
            templates = _FINDING_TEMPLATES.get(prov, [])
            regions = _REGIONS.get(prov, ["global"])

            for tpl in templates:
                count = random.randint(1, 3)  # noqa: S311
                for idx in range(count):
                    fid = _finding_hash(prov, tpl["resource_type"], idx)
                    region = random.choice(regions)  # noqa: S311
                    findings.append(
                        CloudFinding(
                            id=f"find-{fid}",
                            provider=prov,
                            resource_type=tpl["resource_type"],
                            resource_id=f"{tpl['resource_type']}-{fid}",
                            region=region,
                            category=tpl["category"],
                            severity=tpl["severity"],
                            title=tpl["title"],
                            description=f"{tpl['title']} in {region}",
                            cve_id=tpl.get("cve_id", ""),
                            tags={
                                "env": random.choice(  # noqa: S311
                                    ["production", "staging", "dev"]
                                ),
                            },
                        )
                    )

        logger.info(
            "cloud_risk_ranker.collect_findings.done",
            finding_count=len(findings),
        )
        return findings

    # ---------------------------------------------------------------
    # 2. Correlate attacker tactics (MITRE ATT&CK)
    # ---------------------------------------------------------------
    async def correlate_tactics(
        self,
        findings: list[CloudFinding],
    ) -> list[AttackerTactic]:
        """Map findings to MITRE ATT&CK tactics and techniques.

        Correlates each finding's risk category with known
        attacker procedures and active threat campaigns.
        """
        logger.info(
            "cloud_risk_ranker.correlate_tactics",
            finding_count=len(findings),
        )

        if self._threat_intel is not None:
            try:
                raw = await self._threat_intel.correlate(
                    findings=[f.model_dump() for f in findings]
                )
                return [AttackerTactic(**t) for t in raw]
            except Exception:
                logger.exception("cloud_risk_ranker.correlate.intel_error")

        tactics: list[AttackerTactic] = []
        for finding in findings:
            cat = finding.category.value
            mappings = _TACTIC_MAP.get(cat, [])
            for mapping in mappings:
                conf = round(
                    random.uniform(0.6, 0.95),  # noqa: S311
                    2,
                )
                num_campaigns = random.randint(0, 2)  # noqa: S311
                campaigns = random.sample(  # noqa: S311
                    _CAMPAIGNS,
                    min(num_campaigns, len(_CAMPAIGNS)),
                )
                tactics.append(
                    AttackerTactic(
                        id=str(uuid.uuid4())[:8],
                        finding_id=finding.id,
                        tactic_id=mapping["tactic_id"],
                        tactic_name=mapping["tactic_name"],
                        technique_id=mapping["technique_id"],
                        technique_name=mapping["technique_name"],
                        procedure=mapping["procedure"],
                        confidence=conf,
                        known_campaigns=campaigns,
                    )
                )

        logger.info(
            "cloud_risk_ranker.correlate_tactics.done",
            tactic_count=len(tactics),
        )
        return tactics

    # ---------------------------------------------------------------
    # 3. Assess exploitability (EPSS / CISA KEV)
    # ---------------------------------------------------------------
    async def assess_exploitability(
        self,
        findings: list[CloudFinding],
    ) -> list[ExploitabilityAssessment]:
        """Score finding exploitability using EPSS and CISA KEV.

        Assigns exploitability levels and composite scores
        based on exploit maturity, disclosure age, and KEV
        catalog membership.
        """
        logger.info(
            "cloud_risk_ranker.assess_exploitability",
            finding_count=len(findings),
        )

        assessments: list[ExploitabilityAssessment] = []
        for finding in findings:
            has_cve = bool(finding.cve_id)
            epss = (
                round(
                    random.uniform(0.01, 0.92),  # noqa: S311
                    3,
                )
                if has_cve
                else 0.0
            )
            in_kev = has_cve and random.random() > 0.6  # noqa: S311
            days = random.randint(1, 365) if has_cve else 0  # noqa: S311

            if in_kev:
                level = ExploitabilityLevel.ACTIVELY_EXPLOITED
            elif epss > 0.5:
                level = ExploitabilityLevel.EXPLOIT_AVAILABLE
            elif epss > 0.1:
                level = ExploitabilityLevel.PROOF_OF_CONCEPT
            else:
                level = ExploitabilityLevel.THEORETICAL

            # Composite: severity + epss + kev + category
            sev_weight = {
                "critical": 40,
                "high": 30,
                "medium": 20,
                "low": 10,
            }
            base = sev_weight.get(finding.severity, 15)
            epss_contrib = epss * 30
            kev_contrib = 20.0 if in_kev else 0.0
            cat_contrib = (
                10.0
                if finding.category
                in (
                    RiskCategory.IDENTITY_EXPOSURE,
                    RiskCategory.DATA_EXPOSURE,
                )
                else 5.0
            )
            composite = round(
                min(100.0, base + epss_contrib + kev_contrib + cat_contrib),
                1,
            )

            assessments.append(
                ExploitabilityAssessment(
                    id=str(uuid.uuid4())[:8],
                    finding_id=finding.id,
                    level=level,
                    epss_score=epss,
                    in_cisa_kev=in_kev,
                    days_since_disclosure=days,
                    exploit_maturity=level.value,
                    weapon_ready=in_kev or epss > 0.7,
                    composite_score=composite,
                )
            )

        logger.info(
            "cloud_risk_ranker.assess_exploitability.done",
            assessment_count=len(assessments),
        )
        return assessments

    # ---------------------------------------------------------------
    # 4. Generate attack paths
    # ---------------------------------------------------------------
    async def generate_attack_paths(
        self,
        findings: list[CloudFinding],
        tactics: list[AttackerTactic],
        assessments: list[ExploitabilityAssessment],
    ) -> list[AttackPath]:
        """Build attack paths from findings through tactics to impact.

        Chains related findings and tactics into multi-step
        attack scenarios with blast radius and likelihood
        estimates.
        """
        logger.info(
            "cloud_risk_ranker.generate_attack_paths",
            finding_count=len(findings),
            tactic_count=len(tactics),
        )

        assess_map: dict[str, ExploitabilityAssessment] = {a.finding_id: a for a in assessments}
        tactic_map: dict[str, list[AttackerTactic]] = {}
        for t in tactics:
            tactic_map.setdefault(t.finding_id, []).append(t)

        paths: list[AttackPath] = []
        blast_options = [
            "single_resource",
            "account",
            "cross_account",
            "cross_cloud",
        ]
        impact_options = [
            "data_exfiltration",
            "privilege_escalation",
            "service_disruption",
            "ransomware_deployment",
            "cryptomining",
            "supply_chain_compromise",
        ]

        for finding in findings:
            f_tactics = tactic_map.get(finding.id, [])
            f_assess = assess_map.get(finding.id)
            if not f_tactics:
                continue

            steps: list[dict[str, Any]] = [
                {
                    "step": 1,
                    "type": "entry",
                    "finding_id": finding.id,
                    "title": finding.title,
                    "provider": finding.provider,
                },
            ]

            for i, tac in enumerate(f_tactics[:3], start=2):
                steps.append(
                    {
                        "step": i,
                        "type": "technique",
                        "tactic": tac.tactic_name,
                        "technique": tac.technique_name,
                        "procedure": tac.procedure,
                    }
                )

            exploit_score = f_assess.composite_score if f_assess else 50.0
            likelihood = round(min(1.0, exploit_score / 100.0), 2)
            blast = random.choice(blast_options)  # noqa: S311
            impact = random.choice(impact_options)  # noqa: S311
            biz_crit = (
                "critical"
                if finding.severity == "critical"
                else "high"
                if finding.severity == "high"
                else "medium"
            )
            overall = round(
                likelihood * 100 * (1.2 if biz_crit == "critical" else 1.0),
                1,
            )
            overall = min(100.0, overall)

            paths.append(
                AttackPath(
                    id=str(uuid.uuid4())[:8],
                    entry_finding_id=finding.id,
                    steps=steps,
                    impact=impact,
                    blast_radius=blast,
                    likelihood=likelihood,
                    business_criticality=biz_crit,
                    overall_risk_score=overall,
                )
            )

        logger.info(
            "cloud_risk_ranker.generate_attack_paths.done",
            path_count=len(paths),
        )
        return paths

    # ---------------------------------------------------------------
    # 5. Prioritize remediation
    # ---------------------------------------------------------------
    async def prioritize_remediation(
        self,
        findings: list[CloudFinding],
        paths: list[AttackPath],
        assessments: list[ExploitabilityAssessment],
    ) -> list[RemediationPriority]:
        """Rank remediation actions by risk-to-effort ratio.

        Combines attack path risk scores, exploitability,
        and business criticality to produce a prioritized
        remediation list.
        """
        logger.info(
            "cloud_risk_ranker.prioritize_remediation",
            finding_count=len(findings),
            path_count=len(paths),
        )

        path_map: dict[str, AttackPath] = {p.entry_finding_id: p for p in paths}
        assess_map: dict[str, ExploitabilityAssessment] = {a.finding_id: a for a in assessments}

        effort_map = {
            "misconfiguration": ("low", 1.0),
            "network_exposure": ("low", 2.0),
            "vulnerability": ("medium", 4.0),
            "identity_exposure": ("medium", 3.0),
            "data_exposure": ("high", 6.0),
        }

        actions_map: dict[str, str] = {
            "misconfiguration": "Fix configuration per CIS benchmark",
            "vulnerability": "Patch or upgrade affected component",
            "identity_exposure": "Rotate credentials and scope permissions",
            "data_exposure": "Restrict access and enable encryption",
            "network_exposure": "Restrict firewall/SG rules",
        }

        priorities: list[RemediationPriority] = []
        for finding in findings:
            path = path_map.get(finding.id)
            assess = assess_map.get(finding.id)
            risk_score = path.overall_risk_score if path else 50.0
            cat = finding.category.value
            effort_label, hours = effort_map.get(cat, ("medium", 4.0))

            reduction = round(min(100.0, risk_score * 0.8), 1)
            auto = cat in ("misconfiguration", "network_exposure")
            justification = (
                f"Risk score {risk_score:.1f}, "
                f"exploitability {assess.level.value if assess else 'unknown'}, "
                f"blast radius {path.blast_radius if path else 'unknown'}"
            )

            priorities.append(
                RemediationPriority(
                    id=str(uuid.uuid4())[:8],
                    finding_id=finding.id,
                    rank=0,
                    action=actions_map.get(cat, "Investigate and remediate"),
                    effort=effort_label,
                    risk_reduction=reduction,
                    estimated_hours=hours,
                    auto_remediable=auto,
                    business_justification=justification,
                )
            )

        # Sort by risk_reduction desc, effort asc
        effort_order = {"low": 0, "medium": 1, "high": 2}
        priorities.sort(
            key=lambda p: (
                -p.risk_reduction,
                effort_order.get(p.effort, 1),
            )
        )
        for i, p in enumerate(priorities, start=1):
            p.rank = i

        logger.info(
            "cloud_risk_ranker.prioritize_remediation.done",
            priority_count=len(priorities),
        )
        return priorities
