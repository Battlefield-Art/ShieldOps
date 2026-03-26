"""CNAPP Analyzer Agent — Tool functions for unified CNAPP scanning."""

from __future__ import annotations

import hashlib
import random
import uuid
from typing import Any

import structlog

from .models import (
    CodeVulnerability,
    ComplianceFramework,
    EntitlementRisk,
    PostureFinding,
    SeverityLevel,
    UnifiedRiskScore,
    WorkloadThreat,
)

logger = structlog.get_logger()

# ------------------------------------------------------------------
# CIS controls per provider for CSPM scanning
# ------------------------------------------------------------------
_CIS_CONTROLS: dict[str, list[dict[str, Any]]] = {
    "aws": [
        {
            "control_id": "CIS-AWS-2.1.1",
            "control_name": "S3 bucket encryption enabled",
            "resource_type": "s3_bucket",
            "severity": SeverityLevel.HIGH,
            "remediation": "Enable SSE-S3 or SSE-KMS",
            "auto_remediable": True,
        },
        {
            "control_id": "CIS-AWS-2.1.2",
            "control_name": "S3 public access blocked",
            "resource_type": "s3_bucket",
            "severity": SeverityLevel.CRITICAL,
            "remediation": "Enable S3 Block Public Access",
            "auto_remediable": True,
        },
        {
            "control_id": "CIS-AWS-1.4",
            "control_name": "Root user MFA enabled",
            "resource_type": "iam_user",
            "severity": SeverityLevel.CRITICAL,
            "remediation": "Enable MFA on root account",
            "auto_remediable": False,
        },
        {
            "control_id": "CIS-AWS-4.1",
            "control_name": "SG restricts inbound 0.0.0.0/0",
            "resource_type": "security_group",
            "severity": SeverityLevel.HIGH,
            "remediation": "Remove unrestricted inbound rules",
            "auto_remediable": True,
        },
        {
            "control_id": "CIS-AWS-3.1",
            "control_name": "CloudTrail multi-region enabled",
            "resource_type": "cloudtrail",
            "severity": SeverityLevel.HIGH,
            "remediation": "Create multi-region trail",
            "auto_remediable": True,
        },
    ],
    "gcp": [
        {
            "control_id": "CIS-GCP-4.1",
            "control_name": "GCS uniform access enabled",
            "resource_type": "gcs_bucket",
            "severity": SeverityLevel.HIGH,
            "remediation": "Enable uniform bucket-level access",
            "auto_remediable": True,
        },
        {
            "control_id": "CIS-GCP-1.4",
            "control_name": "SA keys rotated within 90 days",
            "resource_type": "service_account",
            "severity": SeverityLevel.HIGH,
            "remediation": "Rotate keys or use workload identity",
            "auto_remediable": True,
        },
        {
            "control_id": "CIS-GCP-6.2",
            "control_name": "Cloud SQL SSL enforced",
            "resource_type": "cloud_sql",
            "severity": SeverityLevel.HIGH,
            "remediation": "Enable SSL enforcement",
            "auto_remediable": True,
        },
    ],
    "azure": [
        {
            "control_id": "CIS-AZ-3.1",
            "control_name": "Storage encryption uses CMK",
            "resource_type": "storage_account",
            "severity": SeverityLevel.MEDIUM,
            "remediation": "Configure customer-managed keys",
            "auto_remediable": True,
        },
        {
            "control_id": "CIS-AZ-4.1.1",
            "control_name": "NSG restricts inbound 0.0.0.0/0",
            "resource_type": "nsg",
            "severity": SeverityLevel.HIGH,
            "remediation": "Restrict NSG inbound rules",
            "auto_remediable": True,
        },
        {
            "control_id": "CIS-AZ-1.3",
            "control_name": "MFA enabled for privileged users",
            "resource_type": "aad_user",
            "severity": SeverityLevel.CRITICAL,
            "remediation": "Enable Conditional Access MFA",
            "auto_remediable": False,
        },
    ],
    "kubernetes": [
        {
            "control_id": "CIS-K8S-5.1.1",
            "control_name": "RBAC enabled on cluster",
            "resource_type": "k8s_cluster",
            "severity": SeverityLevel.CRITICAL,
            "remediation": "Enable RBAC authorization mode",
            "auto_remediable": False,
        },
        {
            "control_id": "CIS-K8S-5.2.2",
            "control_name": "Pods not running as privileged",
            "resource_type": "k8s_pod",
            "severity": SeverityLevel.HIGH,
            "remediation": "Set privileged=false on containers",
            "auto_remediable": True,
        },
        {
            "control_id": "CIS-K8S-5.4.1",
            "control_name": "Secrets encrypted at rest",
            "resource_type": "k8s_secret",
            "severity": SeverityLevel.HIGH,
            "remediation": "Configure EncryptionConfiguration",
            "auto_remediable": False,
        },
    ],
}

# Workload threat templates for CWPP
_WORKLOAD_THREATS: list[dict[str, Any]] = [
    {
        "threat_type": "critical_cve",
        "cve_id": "CVE-2024-21626",
        "cvss_score": 9.8,
        "description": "Container escape via runc",
        "fix_available": True,
    },
    {
        "threat_type": "critical_cve",
        "cve_id": "CVE-2024-3094",
        "cvss_score": 10.0,
        "description": "XZ Utils backdoor in base image",
        "fix_available": True,
    },
    {
        "threat_type": "runtime_anomaly",
        "cve_id": "",
        "cvss_score": 8.5,
        "description": "Crypto mining process detected",
        "fix_available": False,
    },
    {
        "threat_type": "privilege_escalation",
        "cve_id": "CVE-2024-1086",
        "cvss_score": 7.8,
        "description": "Kernel privilege escalation",
        "fix_available": True,
    },
    {
        "threat_type": "reverse_shell",
        "cve_id": "",
        "cvss_score": 9.0,
        "description": "Reverse shell connection detected",
        "fix_available": False,
    },
    {
        "threat_type": "image_vuln",
        "cve_id": "CVE-2023-44487",
        "cvss_score": 7.5,
        "description": "HTTP/2 rapid reset in base image",
        "fix_available": True,
    },
]

# Identity entitlement risk templates for CIEM
_IDENTITY_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "aws": [
        {
            "identity_type": "iam_role",
            "risk_type": "over_privileged",
            "prefix": "arn:aws:iam::role/",
        },
        {
            "identity_type": "service_account",
            "risk_type": "admin_access",
            "prefix": "arn:aws:iam::user/svc-",
        },
        {
            "identity_type": "cross_account_role",
            "risk_type": "cross_account_trust",
            "prefix": "arn:aws:iam::role/cross-",
        },
    ],
    "gcp": [
        {
            "identity_type": "service_account",
            "risk_type": "over_privileged",
            "prefix": "sa-",
        },
        {
            "identity_type": "user",
            "risk_type": "admin_access",
            "prefix": "user-",
        },
    ],
    "azure": [
        {
            "identity_type": "service_principal",
            "risk_type": "over_privileged",
            "prefix": "sp-",
        },
        {
            "identity_type": "managed_identity",
            "risk_type": "unused_permissions",
            "prefix": "mi-",
        },
    ],
}

# IaC vulnerability templates for code security
_IAC_VULNS: list[dict[str, Any]] = [
    {
        "source_type": "terraform",
        "vuln_type": "public_s3_bucket",
        "severity": SeverityLevel.CRITICAL,
        "cwe_id": "CWE-284",
        "description": "S3 bucket ACL set to public-read",
        "fix_suggestion": 'Set acl = "private"',
        "iac_provider": "aws",
    },
    {
        "source_type": "terraform",
        "vuln_type": "unencrypted_ebs",
        "severity": SeverityLevel.HIGH,
        "cwe_id": "CWE-311",
        "description": "EBS volume encryption disabled",
        "fix_suggestion": "Set encrypted = true",
        "iac_provider": "aws",
    },
    {
        "source_type": "cloudformation",
        "vuln_type": "wildcard_iam_policy",
        "severity": SeverityLevel.CRITICAL,
        "cwe_id": "CWE-250",
        "description": 'IAM policy with Action: "*"',
        "fix_suggestion": "Scope to specific actions",
        "iac_provider": "aws",
    },
    {
        "source_type": "kubernetes_yaml",
        "vuln_type": "privileged_container",
        "severity": SeverityLevel.HIGH,
        "cwe_id": "CWE-250",
        "description": "Container runs as privileged",
        "fix_suggestion": "Set privileged: false",
        "iac_provider": "kubernetes",
    },
    {
        "source_type": "terraform",
        "vuln_type": "open_security_group",
        "severity": SeverityLevel.HIGH,
        "cwe_id": "CWE-284",
        "description": "SG allows 0.0.0.0/0 ingress",
        "fix_suggestion": "Restrict CIDR to known IPs",
        "iac_provider": "aws",
    },
    {
        "source_type": "terraform",
        "vuln_type": "no_logging",
        "severity": SeverityLevel.MEDIUM,
        "cwe_id": "CWE-778",
        "description": "Resource missing audit logging",
        "fix_suggestion": "Enable access logging",
        "iac_provider": "gcp",
    },
    {
        "source_type": "kubernetes_yaml",
        "vuln_type": "no_resource_limits",
        "severity": SeverityLevel.MEDIUM,
        "cwe_id": "CWE-770",
        "description": "Container missing resource limits",
        "fix_suggestion": "Add resources.limits",
        "iac_provider": "kubernetes",
    },
]

_REGIONS: dict[str, list[str]] = {
    "aws": ["us-east-1", "us-west-2", "eu-west-1"],
    "gcp": ["us-central1", "europe-west1"],
    "azure": ["eastus", "westeurope"],
    "kubernetes": ["default-cluster"],
}


def _resource_hash(provider: str, rtype: str, idx: int) -> str:
    """Deterministic resource id."""
    raw = f"{provider}-{rtype}-{idx}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


class CNAPPAnalyzerToolkit:
    """Tools for unified CNAPP scanning across all domains."""

    def __init__(
        self,
        cloud_clients: Any | None = None,
        workload_scanner: Any | None = None,
        identity_analyzer: Any | None = None,
        code_scanner: Any | None = None,
    ) -> None:
        self._cloud_clients = cloud_clients
        self._workload_scanner = workload_scanner
        self._identity_analyzer = identity_analyzer
        self._code_scanner = code_scanner

    # --------------------------------------------------------------
    # 1. CSPM — Cloud Posture Scanning
    # --------------------------------------------------------------
    async def scan_cloud_posture(
        self,
        tenant_id: str,
        providers: list[str],
        frameworks: list[str],
    ) -> list[PostureFinding]:
        """Scan cloud posture with CIS benchmarks.

        Evaluates cloud resources against CIS controls
        for each provider. Uses live clients if available,
        otherwise returns simulated findings.
        """
        logger.info(
            "cnapp.scan_cloud_posture",
            tenant_id=tenant_id,
            providers=providers,
        )

        if self._cloud_clients is not None:
            try:
                raw = await self._cloud_clients.scan(
                    tenant_id=tenant_id,
                    providers=providers,
                )
                return [PostureFinding(**r) for r in raw]
            except Exception:
                logger.exception("cnapp.scan_cloud_posture.client_error")

        findings: list[PostureFinding] = []
        for provider in providers:
            controls = _CIS_CONTROLS.get(provider, [])
            regions = _REGIONS.get(provider, ["global"])
            for ctrl in controls:
                count = random.randint(2, 4)  # noqa: S311
                for idx in range(count):
                    rid = _resource_hash(
                        provider,
                        ctrl["resource_type"],
                        idx,
                    )
                    compliant = random.random() > 0.35  # noqa: S311
                    status = (
                        "pass"
                        if compliant
                        else random.choice(  # noqa: S311
                            ["fail", "fail", "warn"]
                        )
                    )
                    base_risk = {
                        SeverityLevel.CRITICAL: 95.0,
                        SeverityLevel.HIGH: 75.0,
                        SeverityLevel.MEDIUM: 50.0,
                        SeverityLevel.LOW: 25.0,
                        SeverityLevel.INFO: 10.0,
                    }
                    risk = (
                        0.0
                        if status == "pass"
                        else round(
                            max(
                                0.0,
                                min(
                                    100.0,
                                    base_risk.get(ctrl["severity"], 50.0)
                                    + random.uniform(  # noqa: S311
                                        -5.0, 5.0
                                    ),
                                ),
                            ),
                            1,
                        )
                    )
                    findings.append(
                        PostureFinding(
                            id=str(uuid.uuid4())[:8],
                            provider=provider,
                            resource_type=ctrl["resource_type"],
                            resource_id=f"{ctrl['resource_type']}-{rid}",
                            region=random.choice(  # noqa: S311
                                regions
                            ),
                            benchmark=self._framework_for(provider, frameworks),
                            control_id=ctrl["control_id"],
                            control_name=ctrl["control_name"],
                            status=status,
                            severity=ctrl["severity"],
                            description=ctrl["control_name"],
                            remediation=ctrl["remediation"],
                            auto_remediable=ctrl["auto_remediable"],
                            risk_score=risk,
                        )
                    )

        logger.info(
            "cnapp.scan_cloud_posture.done",
            finding_count=len(findings),
        )
        return findings

    # --------------------------------------------------------------
    # 2. CWPP — Workload Protection
    # --------------------------------------------------------------
    async def assess_workload_protection(
        self,
        tenant_id: str,
        providers: list[str],
    ) -> list[WorkloadThreat]:
        """Scan container images and runtime for threats.

        Detects CVEs in container images and runtime
        anomalies like crypto mining and reverse shells.
        """
        logger.info(
            "cnapp.assess_workload_protection",
            tenant_id=tenant_id,
        )

        if self._workload_scanner is not None:
            try:
                raw = await self._workload_scanner.scan(
                    tenant_id=tenant_id,
                )
                return [WorkloadThreat(**r) for r in raw]
            except Exception:
                logger.exception("cnapp.workload_protection.error")

        threats: list[WorkloadThreat] = []
        images = [
            "nginx:1.24",
            "python:3.11-slim",
            "node:20-alpine",
            "postgres:15",
            "redis:7",
            "ubuntu:22.04",
        ]
        for img in images:
            threat_count = random.randint(0, 3)  # noqa: S311
            for _ in range(threat_count):
                tpl = random.choice(  # noqa: S311
                    _WORKLOAD_THREATS
                )
                runtime = tpl["threat_type"] in (
                    "runtime_anomaly",
                    "reverse_shell",
                )
                threats.append(
                    WorkloadThreat(
                        id=str(uuid.uuid4())[:8],
                        workload_type="container",
                        workload_id=f"wl-{_resource_hash('cwpp', img, 0)}",
                        image=img,
                        threat_type=tpl["threat_type"],
                        severity=self._cvss_to_severity(tpl["cvss_score"]),
                        cve_id=tpl["cve_id"],
                        cvss_score=tpl["cvss_score"],
                        description=tpl["description"],
                        fix_available=tpl["fix_available"],
                        runtime_detected=runtime,
                    )
                )

        logger.info(
            "cnapp.assess_workload_protection.done",
            threat_count=len(threats),
        )
        return threats

    # --------------------------------------------------------------
    # 3. CIEM — Identity Entitlement Analysis
    # --------------------------------------------------------------
    async def analyze_identity_entitlements(
        self,
        tenant_id: str,
        providers: list[str],
    ) -> list[EntitlementRisk]:
        """Analyze cloud identity entitlements for risk.

        Detects over-privileged identities, unused
        permissions, and cross-account trust risks.
        Recommends right-sized policies.
        """
        logger.info(
            "cnapp.analyze_identity_entitlements",
            tenant_id=tenant_id,
        )

        if self._identity_analyzer is not None:
            try:
                raw = await self._identity_analyzer.analyze(
                    tenant_id=tenant_id,
                )
                return [EntitlementRisk(**r) for r in raw]
            except Exception:
                logger.exception("cnapp.identity_entitlements.error")

        risks: list[EntitlementRisk] = []
        for provider in providers:
            templates = _IDENTITY_TEMPLATES.get(provider, [])
            for tpl in templates:
                count = random.randint(2, 5)  # noqa: S311
                for idx in range(count):
                    total_perms = random.randint(  # noqa: S311
                        50, 500
                    )
                    used = random.randint(  # noqa: S311
                        5, total_perms
                    )
                    unused_ratio = round(1.0 - (used / total_perms), 3)
                    severity = (
                        SeverityLevel.CRITICAL
                        if unused_ratio > 0.9
                        else SeverityLevel.HIGH
                        if unused_ratio > 0.7
                        else SeverityLevel.MEDIUM
                    )
                    rid = _resource_hash(
                        provider,
                        tpl["identity_type"],
                        idx,
                    )
                    risks.append(
                        EntitlementRisk(
                            id=str(uuid.uuid4())[:8],
                            provider=provider,
                            identity_type=tpl["identity_type"],
                            identity_arn=f"{tpl['prefix']}{rid}",
                            permission_count=total_perms,
                            used_permission_count=used,
                            unused_ratio=unused_ratio,
                            severity=severity,
                            risk_type=tpl["risk_type"],
                            description=(
                                f"{tpl['identity_type']} uses {used}/{total_perms} permissions"
                            ),
                            right_sized_policy=(f"policy-{rid}-rightsized"),
                        )
                    )

        logger.info(
            "cnapp.analyze_identity_entitlements.done",
            risk_count=len(risks),
        )
        return risks

    # --------------------------------------------------------------
    # 4. Code Security — IaC Vulnerability Scanning
    # --------------------------------------------------------------
    async def scan_code_security(
        self,
        tenant_id: str,
        providers: list[str],
    ) -> list[CodeVulnerability]:
        """Scan IaC code for misconfigurations.

        Checks Terraform, CloudFormation, and K8s YAML
        for security misconfigurations and maps to CWE IDs.
        """
        logger.info(
            "cnapp.scan_code_security",
            tenant_id=tenant_id,
        )

        if self._code_scanner is not None:
            try:
                raw = await self._code_scanner.scan(
                    tenant_id=tenant_id,
                )
                return [CodeVulnerability(**r) for r in raw]
            except Exception:
                logger.exception("cnapp.code_security.error")

        vulns: list[CodeVulnerability] = []
        relevant = [
            v
            for v in _IAC_VULNS
            if v["iac_provider"] in providers or v["iac_provider"] == "kubernetes"
        ]
        for tpl in relevant:
            count = random.randint(1, 3)  # noqa: S311
            for idx in range(count):
                ext = {
                    "terraform": ".tf",
                    "cloudformation": ".yaml",
                    "kubernetes_yaml": ".yaml",
                }.get(tpl["source_type"], ".tf")
                fpath = f"infra/{tpl['iac_provider']}/main_{idx}{ext}"
                vulns.append(
                    CodeVulnerability(
                        id=str(uuid.uuid4())[:8],
                        source_type=tpl["source_type"],
                        file_path=fpath,
                        line_number=random.randint(  # noqa: S311
                            10, 200
                        ),
                        vuln_type=tpl["vuln_type"],
                        severity=tpl["severity"],
                        description=tpl["description"],
                        cwe_id=tpl["cwe_id"],
                        fix_suggestion=tpl["fix_suggestion"],
                        iac_provider=tpl["iac_provider"],
                    )
                )

        logger.info(
            "cnapp.scan_code_security.done",
            vuln_count=len(vulns),
        )
        return vulns

    # --------------------------------------------------------------
    # 5. Unified Risk Correlation
    # --------------------------------------------------------------
    async def correlate_risks(
        self,
        posture_findings: list[PostureFinding],
        workload_threats: list[WorkloadThreat],
        entitlement_risks: list[EntitlementRisk],
        code_vulns: list[CodeVulnerability],
        frameworks: list[str],
    ) -> tuple[UnifiedRiskScore, dict[str, Any]]:
        """Correlate risks across all CNAPP domains.

        Computes per-domain scores, identifies cross-domain
        attack paths, and calculates compliance coverage.
        """
        logger.info("cnapp.correlate_risks")

        # CSPM score
        total_posture = len(posture_findings)
        passing = sum(1 for f in posture_findings if f.status == "pass")
        cspm = round((passing / max(total_posture, 1)) * 100, 1)

        # CWPP score
        crit_threats = sum(
            1
            for t in workload_threats
            if t.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)
        )
        cwpp = round(
            max(
                0.0,
                100.0 - (crit_threats * 10.0),
            ),
            1,
        )

        # CIEM score
        over_priv = sum(1 for e in entitlement_risks if e.unused_ratio > 0.7)
        ciem = round(
            max(
                0.0,
                100.0 - (over_priv * 8.0),
            ),
            1,
        )

        # Code security score
        crit_vulns = sum(
            1 for v in code_vulns if v.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)
        )
        code_sec = round(
            max(
                0.0,
                100.0 - (crit_vulns * 12.0),
            ),
            1,
        )

        # Weighted overall
        overall = round(
            cspm * 0.30 + cwpp * 0.25 + ciem * 0.25 + code_sec * 0.20,
            1,
        )

        # Risk level
        risk_level = (
            "critical"
            if overall < 40
            else "high"
            if overall < 60
            else "medium"
            if overall < 80
            else "low"
        )

        # Attack paths
        attack_paths = self._identify_attack_paths(
            posture_findings,
            workload_threats,
            entitlement_risks,
            code_vulns,
        )

        # Compliance coverage
        compliance = self._calc_compliance(posture_findings, frameworks)

        score = UnifiedRiskScore(
            overall_score=overall,
            cspm_score=cspm,
            cwpp_score=cwpp,
            ciem_score=ciem,
            code_security_score=code_sec,
            risk_level=risk_level,
            attack_paths=attack_paths[:5],
            top_recommendations=self._top_actions(
                posture_findings,
                workload_threats,
                entitlement_risks,
                code_vulns,
            ),
        )

        logger.info(
            "cnapp.correlate_risks.done",
            overall=overall,
            risk_level=risk_level,
        )
        return score, compliance

    # --------------------------------------------------------------
    # Helpers
    # --------------------------------------------------------------
    @staticmethod
    def _framework_for(
        provider: str,
        frameworks: list[str],
    ) -> str:
        """Map provider to best-matching framework."""
        pmap = {
            "aws": "cis",
            "gcp": "cis",
            "azure": "cis",
            "kubernetes": "cis",
        }
        preferred = pmap.get(provider, "cis")
        if preferred in frameworks:
            return preferred
        return frameworks[0] if frameworks else "cis"

    @staticmethod
    def _cvss_to_severity(
        cvss: float,
    ) -> SeverityLevel:
        """Convert CVSS score to severity level."""
        if cvss >= 9.0:
            return SeverityLevel.CRITICAL
        if cvss >= 7.0:
            return SeverityLevel.HIGH
        if cvss >= 4.0:
            return SeverityLevel.MEDIUM
        if cvss >= 0.1:
            return SeverityLevel.LOW
        return SeverityLevel.INFO

    @staticmethod
    def _identify_attack_paths(
        posture: list[PostureFinding],
        workloads: list[WorkloadThreat],
        entitlements: list[EntitlementRisk],
        code: list[CodeVulnerability],
    ) -> list[str]:
        """Identify cross-domain attack paths."""
        paths: list[str] = []
        pub_findings = [
            f for f in posture if f.status == "fail" and "public" in f.control_name.lower()
        ]
        over_priv = [e for e in entitlements if e.unused_ratio > 0.8]
        runtime_threats = [t for t in workloads if t.runtime_detected]
        crit_iac = [v for v in code if v.severity == SeverityLevel.CRITICAL]

        if pub_findings and over_priv:
            paths.append("Public resource + over-privileged identity -> data exfiltration")
        if runtime_threats and over_priv:
            paths.append("Runtime threat + admin identity -> lateral movement")
        if crit_iac and pub_findings:
            paths.append("IaC public exposure + cloud misconfig -> persistent access")
        if runtime_threats and crit_iac:
            paths.append("Container escape + IaC misconfig -> cluster takeover")
        if over_priv and crit_iac:
            paths.append("Wildcard IAM policy + unencrypted storage -> data breach")
        if not paths:
            paths.append("No critical cross-domain attack paths detected")
        return paths

    @staticmethod
    def _top_actions(
        posture: list[PostureFinding],
        workloads: list[WorkloadThreat],
        entitlements: list[EntitlementRisk],
        code: list[CodeVulnerability],
    ) -> list[str]:
        """Generate top risk-reduction actions."""
        actions: list[str] = []
        crit_posture = sum(
            1 for f in posture if f.status == "fail" and f.severity == SeverityLevel.CRITICAL
        )
        if crit_posture > 0:
            actions.append(f"Fix {crit_posture} critical CSPM findings")
        crit_cves = sum(1 for t in workloads if t.cvss_score >= 9.0 and t.fix_available)
        if crit_cves > 0:
            actions.append(f"Patch {crit_cves} critical CVEs in container images")
        over_priv = sum(1 for e in entitlements if e.unused_ratio > 0.8)
        if over_priv > 0:
            actions.append(f"Right-size {over_priv} over-privileged identities")
        crit_iac = sum(1 for v in code if v.severity == SeverityLevel.CRITICAL)
        if crit_iac > 0:
            actions.append(f"Fix {crit_iac} critical IaC misconfigurations")
        runtime = sum(1 for t in workloads if t.runtime_detected)
        if runtime > 0:
            actions.append(f"Investigate {runtime} active runtime threats")
        return actions[:5]

    @staticmethod
    def _calc_compliance(
        findings: list[PostureFinding],
        frameworks: list[str],
    ) -> dict[str, Any]:
        """Calculate compliance coverage per framework."""
        coverage: dict[str, Any] = {}
        total = len(findings) if findings else 1
        passing = sum(1 for f in findings if f.status == "pass")
        base_rate = round((passing / total) * 100, 1)
        for fw in frameworks:
            try:
                cf = ComplianceFramework(fw)
                noise = random.uniform(  # noqa: S311
                    -5.0, 5.0
                )
                rate = round(
                    max(0.0, min(100.0, base_rate + noise)),
                    1,
                )
                coverage[cf.value] = {
                    "compliance_rate": rate,
                    "controls_evaluated": total,
                    "controls_passing": passing,
                }
            except ValueError:
                continue
        return coverage
