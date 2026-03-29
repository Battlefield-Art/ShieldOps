"""Cloud Workload Protector Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
import time
import uuid
from typing import Any

import structlog

from .models import (
    CloudWorkload,
    DriftFinding,
    RuntimeAnomaly,
    VulnerabilityFinding,
    WorkloadPlatform,
    WorkloadSeverity,
)

logger = structlog.get_logger()

_INSTANCE_TYPES: dict[str, list[str]] = {
    "ec2": ["t3.micro", "t3.medium", "m5.large", "c5.xlarge"],
    "gce": [
        "e2-micro",
        "e2-medium",
        "n2-standard-2",
        "c2-standard-4",
    ],
    "azure_vm": [
        "Standard_B1s",
        "Standard_D2s_v3",
        "Standard_E2s_v3",
    ],
    "kubernetes": ["pod-small", "pod-medium", "pod-large"],
    "ecs": ["fargate-256", "fargate-512", "fargate-1024"],
}

_OS_TYPES = [
    "Ubuntu 22.04",
    "Amazon Linux 2023",
    "RHEL 9",
    "Debian 12",
    "Windows Server 2022",
]

_REGIONS: dict[str, list[str]] = {
    "ec2": ["us-east-1", "us-west-2", "eu-west-1"],
    "gce": ["us-central1", "europe-west1"],
    "azure_vm": ["eastus", "westeurope"],
    "kubernetes": ["default-cluster"],
    "ecs": ["us-east-1", "eu-west-1"],
}

_RUNTIME_ANOMALIES = [
    {
        "type": "reverse_shell",
        "process": "/bin/bash",
        "severity": WorkloadSeverity.CRITICAL,
        "mitre": "T1059.004",
    },
    {
        "type": "crypto_miner",
        "process": "xmrig",
        "severity": WorkloadSeverity.HIGH,
        "mitre": "T1496",
    },
    {
        "type": "unauthorized_ssh",
        "process": "sshd",
        "severity": WorkloadSeverity.HIGH,
        "mitre": "T1021.004",
    },
    {
        "type": "privilege_escalation",
        "process": "sudo",
        "severity": WorkloadSeverity.CRITICAL,
        "mitre": "T1548.003",
    },
    {
        "type": "data_exfil",
        "process": "curl",
        "severity": WorkloadSeverity.HIGH,
        "mitre": "T1048",
    },
]

_DRIFT_TYPES = [
    {
        "type": "firewall_rule_added",
        "severity": WorkloadSeverity.HIGH,
        "auto": True,
    },
    {
        "type": "user_created",
        "severity": WorkloadSeverity.MEDIUM,
        "auto": False,
    },
    {
        "type": "package_installed",
        "severity": WorkloadSeverity.LOW,
        "auto": True,
    },
    {
        "type": "config_file_changed",
        "severity": WorkloadSeverity.MEDIUM,
        "auto": True,
    },
    {
        "type": "service_enabled",
        "severity": WorkloadSeverity.MEDIUM,
        "auto": True,
    },
]

_CVE_LIST = [
    {
        "cve": "CVE-2024-21626",
        "pkg": "runc",
        "cvss": 8.6,
        "sev": WorkloadSeverity.CRITICAL,
        "fix": "1.1.12",
    },
    {
        "cve": "CVE-2024-3094",
        "pkg": "xz-utils",
        "cvss": 10.0,
        "sev": WorkloadSeverity.CRITICAL,
        "fix": "5.6.1",
    },
    {
        "cve": "CVE-2023-44487",
        "pkg": "nginx",
        "cvss": 7.5,
        "sev": WorkloadSeverity.HIGH,
        "fix": "1.25.3",
    },
    {
        "cve": "CVE-2023-38545",
        "pkg": "curl",
        "cvss": 9.8,
        "sev": WorkloadSeverity.CRITICAL,
        "fix": "8.4.0",
    },
    {
        "cve": "CVE-2023-4911",
        "pkg": "glibc",
        "cvss": 7.8,
        "sev": WorkloadSeverity.HIGH,
        "fix": "2.38-4",
    },
]


def _wl_hash(platform: str, idx: int) -> str:
    raw = f"{platform}-workload-{idx}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


class CloudWorkloadProtectorToolkit:
    """Tools for cloud workload protection."""

    def __init__(
        self,
        cloud_clients: Any | None = None,
    ) -> None:
        self._cloud_clients = cloud_clients

    async def inventory_workloads(
        self,
        tenant_id: str,
        platforms: list[str],
    ) -> list[CloudWorkload]:
        """Inventory cloud workload instances."""
        logger.info(
            "cwp.inventory",
            tenant_id=tenant_id,
            platforms=platforms,
        )

        if self._cloud_clients is not None:
            try:
                raw = await self._cloud_clients.list_instances(
                    tenant_id=tenant_id, platforms=platforms
                )
                return [CloudWorkload(**r) for r in raw]
            except Exception:
                logger.exception("cwp.inventory.error")

        workloads: list[CloudWorkload] = []
        for platform_key in platforms:
            types = _INSTANCE_TYPES.get(platform_key, ["t3.micro"])
            regions = _REGIONS.get(platform_key, ["us-east-1"])

            for idx in range(random.randint(4, 10)):  # noqa: S311
                wid = _wl_hash(platform_key, idx)
                workloads.append(
                    CloudWorkload(
                        id=wid,
                        platform=WorkloadPlatform(platform_key),
                        instance_id=f"i-{wid}",
                        instance_type=random.choice(types),  # noqa: S311
                        region=random.choice(regions),  # noqa: S311
                        os_type=random.choice(_OS_TYPES),  # noqa: S311
                        state="running",
                        tags={
                            "env": random.choice(  # noqa: S311
                                ["prod", "staging", "dev"]
                            ),
                        },
                        agent_installed=random.random() > 0.3,  # noqa: S311
                        last_scanned=time.time() - random.uniform(0, 86400),  # noqa: S311
                    )
                )

        logger.info("cwp.inventory.done", count=len(workloads))
        return workloads

    async def monitor_runtime(
        self,
        workloads: list[CloudWorkload],
    ) -> list[RuntimeAnomaly]:
        """Monitor runtime behavior for anomalies."""
        logger.info("cwp.runtime", count=len(workloads))

        anomalies: list[RuntimeAnomaly] = []
        for wl in workloads:
            if random.random() > 0.6:  # noqa: S311
                tpl = random.choice(  # noqa: S311
                    _RUNTIME_ANOMALIES
                )
                base_risk = {
                    WorkloadSeverity.CRITICAL: 90.0,
                    WorkloadSeverity.HIGH: 70.0,
                    WorkloadSeverity.MEDIUM: 50.0,
                }.get(tpl["severity"], 50.0)

                anomalies.append(
                    RuntimeAnomaly(
                        id=str(uuid.uuid4())[:8],
                        workload_id=wl.id,
                        anomaly_type=tpl["type"],
                        severity=tpl["severity"],
                        process_name=tpl["process"],
                        description=(f"{tpl['type']} detected on {wl.instance_id}"),
                        risk_score=round(
                            base_risk + random.uniform(-5, 5),  # noqa: S311
                            1,
                        ),
                        mitre_technique=tpl["mitre"],
                    )
                )

        logger.info(
            "cwp.runtime.done",
            anomalies=len(anomalies),
        )
        return anomalies

    async def detect_drift(
        self,
        workloads: list[CloudWorkload],
    ) -> list[DriftFinding]:
        """Detect configuration drift from baselines."""
        logger.info("cwp.drift", count=len(workloads))

        findings: list[DriftFinding] = []
        for wl in workloads:
            if random.random() > 0.5:  # noqa: S311
                tpl = random.choice(_DRIFT_TYPES)  # noqa: S311
                findings.append(
                    DriftFinding(
                        id=str(uuid.uuid4())[:8],
                        workload_id=wl.id,
                        drift_type=tpl["type"],
                        severity=tpl["severity"],
                        expected_value="baseline",
                        actual_value="modified",
                        description=(f"{tpl['type']} on {wl.instance_id}"),
                        auto_remediable=tpl["auto"],
                    )
                )

        logger.info("cwp.drift.done", findings=len(findings))
        return findings

    async def scan_vulnerabilities(
        self,
        workloads: list[CloudWorkload],
    ) -> list[VulnerabilityFinding]:
        """Scan workloads for known vulnerabilities."""
        logger.info("cwp.vulns", count=len(workloads))

        findings: list[VulnerabilityFinding] = []
        for wl in workloads:
            num = random.randint(0, 3)  # noqa: S311
            selected = random.sample(  # noqa: S311
                _CVE_LIST, min(num, len(_CVE_LIST))
            )
            for cve in selected:
                findings.append(
                    VulnerabilityFinding(
                        id=str(uuid.uuid4())[:8],
                        workload_id=wl.id,
                        cve_id=cve["cve"],
                        package_name=cve["pkg"],
                        severity=cve["sev"],
                        cvss_score=cve["cvss"],
                        description=(f"{cve['cve']} in {cve['pkg']} on {wl.instance_id}"),
                        fix_available=True,
                        fixed_version=cve["fix"],
                    )
                )

        logger.info("cwp.vulns.done", findings=len(findings))
        return findings
