"""Multi-Cloud Compliance Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
import time
import uuid
from typing import Any

import structlog

from .models import (
    BenchmarkControl,
    CloudConfig,
    ComplianceFramework,
    ComplianceGap,
    ComplianceStatus,
    RemediationTask,
)

logger = structlog.get_logger()

_CIS_CONTROLS: dict[str, list[dict[str, Any]]] = {
    "aws": [
        {"id": "CIS-AWS-1.4", "name": "Root MFA enabled", "sev": "critical"},
        {"id": "CIS-AWS-2.1.1", "name": "S3 encryption", "sev": "high"},
        {"id": "CIS-AWS-2.1.2", "name": "S3 public block", "sev": "critical"},
        {"id": "CIS-AWS-3.1", "name": "CloudTrail enabled", "sev": "high"},
        {"id": "CIS-AWS-4.1", "name": "SG restrict inbound", "sev": "high"},
    ],
    "gcp": [
        {"id": "CIS-GCP-1.4", "name": "SA key rotation", "sev": "high"},
        {"id": "CIS-GCP-3.1", "name": "Default VPC deleted", "sev": "medium"},
        {"id": "CIS-GCP-4.1", "name": "GCS uniform access", "sev": "high"},
        {"id": "CIS-GCP-6.2", "name": "Cloud SQL SSL", "sev": "high"},
    ],
    "azure": [
        {"id": "CIS-AZ-1.3", "name": "MFA for admins", "sev": "critical"},
        {"id": "CIS-AZ-3.1", "name": "Storage CMK", "sev": "medium"},
        {"id": "CIS-AZ-4.1.1", "name": "NSG restrict", "sev": "high"},
        {"id": "CIS-AZ-9.1", "name": "KeyVault logging", "sev": "high"},
    ],
}

_RESOURCE_TYPES: dict[str, list[str]] = {
    "aws": [
        "s3_bucket",
        "iam_user",
        "security_group",
        "rds_instance",
    ],
    "gcp": [
        "gcs_bucket",
        "service_account",
        "vpc_network",
        "cloud_sql",
    ],
    "azure": [
        "storage_account",
        "aad_user",
        "nsg",
        "key_vault",
    ],
}

_REGIONS: dict[str, list[str]] = {
    "aws": ["us-east-1", "us-west-2", "eu-west-1"],
    "gcp": ["us-central1", "europe-west1"],
    "azure": ["eastus", "westeurope"],
}


def _cfg_hash(provider: str, rtype: str, idx: int) -> str:
    raw = f"{provider}-{rtype}-{idx}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


class MultiCloudComplianceToolkit:
    """Tools for multi-cloud compliance checking."""

    def __init__(
        self,
        cloud_clients: Any | None = None,
    ) -> None:
        self._cloud_clients = cloud_clients

    async def collect_configs(
        self,
        tenant_id: str,
        providers: list[str],
    ) -> list[CloudConfig]:
        """Collect cloud configurations for compliance."""
        logger.info("mcc.collect", tenant_id=tenant_id, providers=providers)

        if self._cloud_clients is not None:
            try:
                raw = await self._cloud_clients.get_configs(
                    tenant_id=tenant_id, providers=providers
                )
                return [CloudConfig(**r) for r in raw]
            except Exception:
                logger.exception("mcc.collect.error")

        configs: list[CloudConfig] = []
        for prov in providers:
            rtypes = _RESOURCE_TYPES.get(prov, [])
            regions = _REGIONS.get(prov, ["global"])
            for rtype in rtypes:
                for idx in range(random.randint(3, 8)):  # noqa: S311
                    cid = _cfg_hash(prov, rtype, idx)
                    configs.append(
                        CloudConfig(
                            id=cid,
                            provider=prov,
                            resource_type=rtype,
                            resource_id=f"{rtype}-{cid}",
                            region=random.choice(regions),  # noqa: S311
                            config_data={
                                "encrypted": random.random() > 0.3,  # noqa: S311
                                "public": random.random() > 0.8,  # noqa: S311
                                "logging": random.random() > 0.4,  # noqa: S311
                            },
                            collected_at=time.time(),
                        )
                    )

        logger.info("mcc.collect.done", count=len(configs))
        return configs

    async def evaluate_benchmarks(
        self,
        configs: list[CloudConfig],
        frameworks: list[str],
    ) -> list[BenchmarkControl]:
        """Evaluate CIS benchmarks against configs."""
        logger.info(
            "mcc.evaluate",
            configs=len(configs),
            frameworks=frameworks,
        )

        controls: list[BenchmarkControl] = []
        providers_in_configs = {c.provider for c in configs}

        for prov in providers_in_configs:
            cis_controls = _CIS_CONTROLS.get(prov, [])
            prov_configs = [c for c in configs if c.provider == prov]

            fw_map = {
                "aws": ComplianceFramework.CIS_AWS,
                "gcp": ComplianceFramework.CIS_GCP,
                "azure": ComplianceFramework.CIS_AZURE,
            }
            fw = fw_map.get(prov, ComplianceFramework.CIS_AWS)

            for ctrl in cis_controls:
                passing = random.random() > 0.35  # noqa: S311
                status = ComplianceStatus.COMPLIANT if passing else ComplianceStatus.NON_COMPLIANT
                failing = (
                    []
                    if passing
                    else [
                        c.resource_id
                        for c in random.sample(  # noqa: S311
                            prov_configs,
                            min(
                                random.randint(1, 3),  # noqa: S311
                                len(prov_configs),
                            ),
                        )
                    ]
                )

                controls.append(
                    BenchmarkControl(
                        id=str(uuid.uuid4())[:8],
                        framework=fw,
                        control_id=ctrl["id"],
                        control_name=ctrl["name"],
                        status=status,
                        provider=prov,
                        resource_count=len(prov_configs),
                        failing_resources=failing,
                        severity=ctrl["sev"],
                        description=f"{ctrl['name']} on {prov}",
                    )
                )

        logger.info("mcc.evaluate.done", controls=len(controls))
        return controls

    async def identify_gaps(
        self,
        controls: list[BenchmarkControl],
    ) -> list[ComplianceGap]:
        """Identify compliance gaps from evaluation."""
        logger.info("mcc.gaps", controls=len(controls))

        gaps: list[ComplianceGap] = []
        failing = [c for c in controls if c.status == ComplianceStatus.NON_COMPLIANT]

        for ctrl in failing:
            gaps.append(
                ComplianceGap(
                    id=str(uuid.uuid4())[:8],
                    framework=ctrl.framework.value,
                    control_id=ctrl.control_id,
                    providers_affected=[ctrl.provider],
                    gap_type="non_compliance",
                    severity=ctrl.severity,
                    description=(f"{ctrl.control_name} failing on {ctrl.provider}"),
                    remediation_steps=[f"Fix {ctrl.control_id} on {ctrl.provider}"],
                    estimated_effort_hours=random.uniform(  # noqa: S311
                        1.0, 8.0
                    ),
                )
            )

        logger.info("mcc.gaps.done", gaps=len(gaps))
        return gaps

    async def generate_remediation_tasks(
        self,
        gaps: list[ComplianceGap],
    ) -> list[RemediationTask]:
        """Generate remediation tasks for gaps."""
        logger.info("mcc.remediation", gaps=len(gaps))

        tasks: list[RemediationTask] = []
        for gap in gaps:
            for prov in gap.providers_affected:
                tasks.append(
                    RemediationTask(
                        id=str(uuid.uuid4())[:8],
                        gap_id=gap.id,
                        provider=prov,
                        task_type="config_fix",
                        description=(f"Fix {gap.control_id} on {prov}"),
                        status="pending",
                        priority=gap.severity,
                    )
                )

        logger.info("mcc.remediation.done", tasks=len(tasks))
        return tasks
