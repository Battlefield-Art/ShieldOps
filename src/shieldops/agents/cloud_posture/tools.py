"""Cloud Posture Agent — Tool functions for CSPM scanning and remediation."""

from __future__ import annotations

import hashlib
import random
import time
import uuid
from typing import Any

import structlog

from .models import (
    BenchmarkFramework,
    BenchmarkResult,
    CloudProvider,
    CloudResource,
    Misconfiguration,
    RemediationAction,
    SeverityLevel,
)

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# CIS Controls per provider — key controls evaluated during benchmark scans
# ---------------------------------------------------------------------------
CIS_CONTROLS: dict[str, list[dict[str, Any]]] = {
    "aws": [
        {
            "control_id": "CIS-AWS-2.1.1",
            "control_name": "Ensure S3 bucket encryption is enabled",
            "resource_type": "s3_bucket",
            "severity": SeverityLevel.HIGH,
            "remediation": "Enable default SSE-S3 or SSE-KMS encryption on bucket",
            "auto_remediable": True,
        },
        {
            "control_id": "CIS-AWS-2.1.2",
            "control_name": "Ensure S3 bucket public access is blocked",
            "resource_type": "s3_bucket",
            "severity": SeverityLevel.CRITICAL,
            "remediation": "Enable S3 Block Public Access at account and bucket level",
            "auto_remediable": True,
        },
        {
            "control_id": "CIS-AWS-1.4",
            "control_name": "Ensure IAM root user MFA is enabled",
            "resource_type": "iam_user",
            "severity": SeverityLevel.CRITICAL,
            "remediation": "Enable MFA on root account via IAM console",
            "auto_remediable": False,
        },
        {
            "control_id": "CIS-AWS-1.16",
            "control_name": "Ensure IAM policies are attached only to groups or roles",
            "resource_type": "iam_policy",
            "severity": SeverityLevel.MEDIUM,
            "remediation": "Remove direct user policy attachments; use groups/roles",
            "auto_remediable": True,
        },
        {
            "control_id": "CIS-AWS-3.1",
            "control_name": "Ensure CloudTrail is enabled in all regions",
            "resource_type": "cloudtrail",
            "severity": SeverityLevel.HIGH,
            "remediation": "Create multi-region CloudTrail trail with log validation",
            "auto_remediable": True,
        },
        {
            "control_id": "CIS-AWS-4.1",
            "control_name": "Ensure security groups restrict inbound 0.0.0.0/0",
            "resource_type": "security_group",
            "severity": SeverityLevel.HIGH,
            "remediation": "Remove 0.0.0.0/0 inbound rules on non-web ports",
            "auto_remediable": True,
        },
        {
            "control_id": "CIS-AWS-2.3.1",
            "control_name": "Ensure RDS encryption at rest is enabled",
            "resource_type": "rds_instance",
            "severity": SeverityLevel.HIGH,
            "remediation": "Enable encryption at rest on RDS instances via snapshot/restore",
            "auto_remediable": False,
        },
    ],
    "gcp": [
        {
            "control_id": "CIS-GCP-3.1",
            "control_name": "Ensure default network is deleted",
            "resource_type": "vpc_network",
            "severity": SeverityLevel.MEDIUM,
            "remediation": "Delete default VPC network and create custom networks",
            "auto_remediable": False,
        },
        {
            "control_id": "CIS-GCP-4.1",
            "control_name": "Ensure GCS bucket uniform access is enabled",
            "resource_type": "gcs_bucket",
            "severity": SeverityLevel.HIGH,
            "remediation": "Enable uniform bucket-level access on all GCS buckets",
            "auto_remediable": True,
        },
        {
            "control_id": "CIS-GCP-1.4",
            "control_name": "Ensure service account keys are rotated within 90 days",
            "resource_type": "service_account",
            "severity": SeverityLevel.HIGH,
            "remediation": "Rotate service account keys or use workload identity",
            "auto_remediable": True,
        },
        {
            "control_id": "CIS-GCP-6.2",
            "control_name": "Ensure Cloud SQL has SSL enforcement enabled",
            "resource_type": "cloud_sql",
            "severity": SeverityLevel.HIGH,
            "remediation": "Enable SSL enforcement on Cloud SQL instances",
            "auto_remediable": True,
        },
    ],
    "azure": [
        {
            "control_id": "CIS-AZ-3.1",
            "control_name": "Ensure storage account encryption uses CMK",
            "resource_type": "storage_account",
            "severity": SeverityLevel.MEDIUM,
            "remediation": "Configure customer-managed keys for storage account encryption",
            "auto_remediable": True,
        },
        {
            "control_id": "CIS-AZ-4.1.1",
            "control_name": "Ensure NSG restricts inbound from 0.0.0.0/0",
            "resource_type": "nsg",
            "severity": SeverityLevel.HIGH,
            "remediation": "Remove or restrict NSG rules allowing unrestricted inbound",
            "auto_remediable": True,
        },
        {
            "control_id": "CIS-AZ-1.3",
            "control_name": "Ensure MFA is enabled for all privileged users",
            "resource_type": "aad_user",
            "severity": SeverityLevel.CRITICAL,
            "remediation": "Enable Conditional Access policy requiring MFA for admins",
            "auto_remediable": False,
        },
        {
            "control_id": "CIS-AZ-9.1",
            "control_name": "Ensure Azure Key Vault logging is enabled",
            "resource_type": "key_vault",
            "severity": SeverityLevel.HIGH,
            "remediation": "Enable diagnostic settings with AuditEvent on Key Vault",
            "auto_remediable": True,
        },
    ],
    "kubernetes": [
        {
            "control_id": "CIS-K8S-5.1.1",
            "control_name": "Ensure RBAC is enabled on the cluster",
            "resource_type": "k8s_cluster",
            "severity": SeverityLevel.CRITICAL,
            "remediation": "Enable RBAC authorization mode on the API server",
            "auto_remediable": False,
        },
        {
            "control_id": "CIS-K8S-5.2.2",
            "control_name": "Ensure pods do not run as privileged",
            "resource_type": "k8s_pod",
            "severity": SeverityLevel.HIGH,
            "remediation": "Set securityContext.privileged=false on all containers",
            "auto_remediable": True,
        },
        {
            "control_id": "CIS-K8S-5.7.3",
            "control_name": "Ensure network policies are defined for all namespaces",
            "resource_type": "k8s_namespace",
            "severity": SeverityLevel.MEDIUM,
            "remediation": "Create NetworkPolicy resources for each namespace",
            "auto_remediable": True,
        },
        {
            "control_id": "CIS-K8S-5.4.1",
            "control_name": "Ensure secrets are encrypted at rest",
            "resource_type": "k8s_secret",
            "severity": SeverityLevel.HIGH,
            "remediation": "Configure EncryptionConfiguration with aescbc or secretbox",
            "auto_remediable": False,
        },
    ],
}

# Simulated resource inventories per provider
_RESOURCE_TEMPLATES: dict[str, list[dict[str, str]]] = {
    "aws": [
        {"resource_type": "s3_bucket", "prefix": "s3-"},
        {"resource_type": "iam_user", "prefix": "iam-user-"},
        {"resource_type": "iam_policy", "prefix": "iam-pol-"},
        {"resource_type": "cloudtrail", "prefix": "trail-"},
        {"resource_type": "security_group", "prefix": "sg-"},
        {"resource_type": "rds_instance", "prefix": "rds-"},
    ],
    "gcp": [
        {"resource_type": "vpc_network", "prefix": "vpc-"},
        {"resource_type": "gcs_bucket", "prefix": "gcs-"},
        {"resource_type": "service_account", "prefix": "sa-"},
        {"resource_type": "cloud_sql", "prefix": "sql-"},
    ],
    "azure": [
        {"resource_type": "storage_account", "prefix": "sa-"},
        {"resource_type": "nsg", "prefix": "nsg-"},
        {"resource_type": "aad_user", "prefix": "aad-"},
        {"resource_type": "key_vault", "prefix": "kv-"},
    ],
    "kubernetes": [
        {"resource_type": "k8s_cluster", "prefix": "cluster-"},
        {"resource_type": "k8s_pod", "prefix": "pod-"},
        {"resource_type": "k8s_namespace", "prefix": "ns-"},
        {"resource_type": "k8s_secret", "prefix": "secret-"},
    ],
}

_REGIONS: dict[str, list[str]] = {
    "aws": ["us-east-1", "us-west-2", "eu-west-1"],
    "gcp": ["us-central1", "europe-west1", "asia-east1"],
    "azure": ["eastus", "westeurope", "southeastasia"],
    "kubernetes": ["default-cluster"],
}


def _resource_hash(provider: str, rtype: str, idx: int) -> str:
    """Deterministic resource id."""
    raw = f"{provider}-{rtype}-{idx}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


class CloudPostureToolkit:
    """Tools for multi-cloud CSPM scanning, benchmark assessment, and remediation."""

    def __init__(
        self,
        cloud_clients: Any | None = None,
        benchmark_db: Any | None = None,
    ) -> None:
        self._cloud_clients = cloud_clients
        self._benchmark_db = benchmark_db

    # ------------------------------------------------------------------
    # 1. Scan cloud resources
    # ------------------------------------------------------------------
    async def scan_cloud_resources(
        self,
        tenant_id: str,
        providers: list[str],
    ) -> list[CloudResource]:
        """Enumerate resources across the requested cloud providers.

        Uses live cloud clients if available; otherwise returns simulated
        resource inventories for demonstration and testing.
        """
        logger.info(
            "cloud_posture.scan_cloud_resources",
            tenant_id=tenant_id,
            providers=providers,
        )

        if self._cloud_clients is not None:
            try:
                raw = await self._cloud_clients.scan(tenant_id=tenant_id, providers=providers)
                return [CloudResource(**r) for r in raw]
            except Exception:
                logger.exception("cloud_posture.scan_cloud_resources.client_error")

        # Mock fallback — generate representative resources
        resources: list[CloudResource] = []
        for provider_key in providers:
            templates = _RESOURCE_TEMPLATES.get(provider_key, [])
            regions = _REGIONS.get(provider_key, ["global"])

            for tpl in templates:
                count = random.randint(2, 5)  # noqa: S311
                for idx in range(count):
                    rid = _resource_hash(provider_key, tpl["resource_type"], idx)
                    region = random.choice(regions)  # noqa: S311
                    resources.append(
                        CloudResource(
                            id=f"{tpl['prefix']}{rid}",
                            provider=CloudProvider(provider_key),
                            resource_type=tpl["resource_type"],
                            resource_id=f"{tpl['prefix']}{rid}",
                            region=region,
                            tags={
                                "env": random.choice(  # noqa: S311
                                    ["production", "staging", "dev"]
                                ),
                                "team": random.choice(  # noqa: S311
                                    ["platform", "security", "data"]
                                ),
                            },
                            compliant=random.random() > 0.35,  # noqa: S311
                            last_scanned=time.time(),
                        )
                    )

        logger.info(
            "cloud_posture.scan_cloud_resources.done",
            resource_count=len(resources),
        )
        return resources

    # ------------------------------------------------------------------
    # 2. Assess benchmarks
    # ------------------------------------------------------------------
    async def assess_benchmarks(
        self,
        resources: list[CloudResource],
        frameworks: list[str],
    ) -> list[BenchmarkResult]:
        """Evaluate CIS/NIST controls against discovered resources.

        Maps each resource to the applicable controls from the requested
        frameworks and produces pass/fail/warn results.
        """
        logger.info(
            "cloud_posture.assess_benchmarks",
            resource_count=len(resources),
            frameworks=frameworks,
        )

        if self._benchmark_db is not None:
            try:
                raw = await self._benchmark_db.assess(
                    resources=[r.model_dump() for r in resources],
                    frameworks=frameworks,
                )
                return [BenchmarkResult(**b) for b in raw]
            except Exception:
                logger.exception("cloud_posture.assess_benchmarks.db_error")

        # Mock fallback — evaluate controls per provider
        results: list[BenchmarkResult] = []
        resource_by_type: dict[str, list[CloudResource]] = {}
        for r in resources:
            resource_by_type.setdefault(r.resource_type, []).append(r)

        for provider_key in {r.provider.value for r in resources}:
            controls = CIS_CONTROLS.get(provider_key, [])
            for ctrl in controls:
                matching = resource_by_type.get(ctrl["resource_type"], [])
                for res in matching:
                    # Simulate compliance status
                    status = (
                        "pass" if res.compliant else random.choice(["fail", "fail", "warn"])  # noqa: S311
                    )

                    fw = self._framework_for_provider(provider_key, frameworks)
                    results.append(
                        BenchmarkResult(
                            id=str(uuid.uuid4())[:8],
                            framework=fw,
                            control_id=ctrl["control_id"],
                            control_name=ctrl["control_name"],
                            resource_id=res.resource_id,
                            status=status,
                            severity=ctrl["severity"],
                            description=(
                                f"{ctrl['control_name']} — "
                                f"resource {res.resource_id} in {res.region}"
                            ),
                            remediation=ctrl["remediation"],
                        )
                    )

        logger.info(
            "cloud_posture.assess_benchmarks.done",
            result_count=len(results),
        )
        return results

    # ------------------------------------------------------------------
    # 3. Detect misconfigurations
    # ------------------------------------------------------------------
    async def detect_misconfigurations(
        self,
        results: list[BenchmarkResult],
    ) -> list[Misconfiguration]:
        """Extract actionable misconfigurations from failing benchmark results.

        Assigns risk scores based on severity and calculates whether the
        misconfiguration can be auto-remediated.
        """
        logger.info(
            "cloud_posture.detect_misconfigurations",
            result_count=len(results),
        )

        severity_risk: dict[SeverityLevel, float] = {
            SeverityLevel.CRITICAL: 95.0,
            SeverityLevel.HIGH: 75.0,
            SeverityLevel.MEDIUM: 50.0,
            SeverityLevel.LOW: 25.0,
            SeverityLevel.INFO: 10.0,
        }

        misconfigs: list[Misconfiguration] = []
        for r in results:
            if r.status == "pass":
                continue

            # Look up auto-remediable flag from CIS_CONTROLS
            auto_rem = self._is_auto_remediable(r.control_id)
            base_risk = severity_risk.get(r.severity, 50.0)
            noise = random.uniform(-5.0, 5.0)  # noqa: S311
            risk = round(max(0.0, min(100.0, base_risk + noise)), 1)

            # Determine provider from control_id prefix
            provider = self._provider_from_control(r.control_id)

            misconfigs.append(
                Misconfiguration(
                    id=str(uuid.uuid4())[:8],
                    resource_id=r.resource_id,
                    provider=provider,
                    misconfig_type=r.control_name,
                    severity=r.severity,
                    description=r.description,
                    cis_reference=r.control_id,
                    auto_remediable=auto_rem,
                    risk_score=risk,
                )
            )

        logger.info(
            "cloud_posture.detect_misconfigurations.done",
            misconfig_count=len(misconfigs),
        )
        return misconfigs

    # ------------------------------------------------------------------
    # 4. Remediate misconfigurations
    # ------------------------------------------------------------------
    async def remediate_misconfigs(
        self,
        misconfigs: list[Misconfiguration],
    ) -> list[RemediationAction]:
        """Auto-fix remediable misconfigurations.

        Only applies remediation to misconfigurations flagged as
        auto_remediable. In production, this would invoke cloud APIs
        via connectors. In mock mode, simulates successful remediation.
        """
        logger.info(
            "cloud_posture.remediate_misconfigs",
            misconfig_count=len(misconfigs),
        )

        actions: list[RemediationAction] = []
        for mc in misconfigs:
            if not mc.auto_remediable:
                continue

            # Simulate remediation
            success = random.random() > 0.1  # noqa: S311 — 90% success rate

            actions.append(
                RemediationAction(
                    id=str(uuid.uuid4())[:8],
                    misconfig_id=mc.id,
                    action=f"auto_fix_{mc.cis_reference.lower().replace('-', '_')}",
                    target=mc.resource_id,
                    description=f"Auto-remediate: {mc.misconfig_type}",
                    applied=True,
                    success=success,
                    rollback_available=True,
                )
            )

        logger.info(
            "cloud_posture.remediate_misconfigs.done",
            action_count=len(actions),
            success_count=sum(1 for a in actions if a.success),
        )
        return actions

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _framework_for_provider(
        provider: str,
        frameworks: list[str],
    ) -> BenchmarkFramework:
        """Map a provider key to the best-matching requested framework."""
        provider_map: dict[str, BenchmarkFramework] = {
            "aws": BenchmarkFramework.CIS_AWS,
            "gcp": BenchmarkFramework.CIS_GCP,
            "azure": BenchmarkFramework.CIS_AZURE,
            "kubernetes": BenchmarkFramework.CIS_K8S,
        }
        preferred = provider_map.get(provider, BenchmarkFramework.CIS_AWS)
        if preferred.value in frameworks:
            return preferred
        # Fallback to first matching framework
        for fw in frameworks:
            try:
                return BenchmarkFramework(fw)
            except ValueError:
                continue
        return preferred

    @staticmethod
    def _is_auto_remediable(control_id: str) -> bool:
        """Check if a control is auto-remediable by looking up CIS_CONTROLS."""
        for provider_controls in CIS_CONTROLS.values():
            for ctrl in provider_controls:
                if ctrl["control_id"] == control_id:
                    return ctrl.get("auto_remediable", False)  # type: ignore[no-any-return]
        return False

    @staticmethod
    def _provider_from_control(control_id: str) -> CloudProvider:
        """Infer cloud provider from CIS control ID prefix."""
        cid = control_id.upper()
        if "AWS" in cid:
            return CloudProvider.AWS
        if "GCP" in cid:
            return CloudProvider.GCP
        if "AZ" in cid:
            return CloudProvider.AZURE
        if "K8S" in cid:
            return CloudProvider.KUBERNETES
        return CloudProvider.AWS
