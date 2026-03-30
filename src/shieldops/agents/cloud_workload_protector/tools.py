"""Cloud Workload Protector Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
import uuid
from typing import Any

import structlog

from .models import (
    ContainmentAction,
    DriftFinding,
    RuntimeAnomaly,
    VulnerabilityFinding,
    WorkloadInventory,
    WorkloadSeverity,
    WorkloadType,
)

logger = structlog.get_logger()

# ---------------------------------------------------------------
# Mock workload definitions
# ---------------------------------------------------------------
_MOCK_WORKLOADS: list[dict[str, Any]] = [
    {
        "workload_type": WorkloadType.CONTAINER,
        "name": "api-gateway",
        "namespace": "production",
        "image": "registry.example.com/api-gw:3.2.1",
        "host": "node-prod-01",
        "region": "us-east-1",
        "cloud_provider": "aws",
        "ports": [8080, 8443],
        "labels": {
            "app": "api-gateway",
            "tier": "edge",
        },
    },
    {
        "workload_type": WorkloadType.KUBERNETES_POD,
        "name": "payment-service",
        "namespace": "production",
        "image": "registry.example.com/payment:2.1.0",
        "host": "node-prod-02",
        "region": "us-east-1",
        "cloud_provider": "aws",
        "ports": [9090],
        "labels": {
            "app": "payment",
            "tier": "backend",
        },
    },
    {
        "workload_type": WorkloadType.CONTAINER,
        "name": "ml-inference",
        "namespace": "ml-workloads",
        "image": "registry.example.com/ml-serve:1.4.0",
        "host": "gpu-node-01",
        "region": "us-west-2",
        "cloud_provider": "aws",
        "ports": [8501],
        "privileged": True,
        "labels": {
            "app": "ml-inference",
            "tier": "compute",
        },
    },
    {
        "workload_type": WorkloadType.VM,
        "name": "db-primary",
        "namespace": "databases",
        "image": "ubuntu-22.04-lts",
        "host": "vm-db-prod-01",
        "region": "eu-west-1",
        "cloud_provider": "aws",
        "ports": [5432, 22],
        "labels": {
            "app": "postgres",
            "tier": "data",
        },
    },
    {
        "workload_type": WorkloadType.SERVERLESS,
        "name": "event-processor",
        "namespace": "event-bus",
        "image": "lambda:event-proc-v4",
        "host": "lambda-us-east-1",
        "region": "us-east-1",
        "cloud_provider": "aws",
        "ports": [],
        "labels": {
            "app": "event-proc",
            "tier": "async",
        },
    },
    {
        "workload_type": WorkloadType.KUBERNETES_POD,
        "name": "redis-cache",
        "namespace": "production",
        "image": "redis:7.2-alpine",
        "host": "node-prod-03",
        "region": "us-east-1",
        "cloud_provider": "aws",
        "ports": [6379],
        "labels": {
            "app": "redis",
            "tier": "cache",
        },
    },
    {
        "workload_type": WorkloadType.CONTAINER,
        "name": "log-collector",
        "namespace": "observability",
        "image": "fluent/fluentd:v1.16",
        "host": "node-prod-01",
        "region": "us-east-1",
        "cloud_provider": "aws",
        "privileged": True,
        "ports": [24224],
        "labels": {
            "app": "fluentd",
            "tier": "infra",
        },
    },
    {
        "workload_type": WorkloadType.BARE_METAL,
        "name": "etcd-cluster-0",
        "namespace": "kube-system",
        "image": "etcd:3.5.12",
        "host": "bm-ctrl-01",
        "region": "us-east-1",
        "cloud_provider": "on-prem",
        "ports": [2379, 2380],
        "labels": {
            "app": "etcd",
            "tier": "control-plane",
        },
    },
]

# ---------------------------------------------------------------
# Mock anomaly patterns
# ---------------------------------------------------------------
_ANOMALY_PATTERNS: list[dict[str, Any]] = [
    {
        "anomaly_type": "container_escape_attempt",
        "severity": WorkloadSeverity.CRITICAL,
        "process": "nsenter",
        "syscall": "setns",
        "container_escape": True,
        "description": (
            "Process nsenter invoked setns syscall to enter host namespace from container"
        ),
    },
    {
        "anomaly_type": "crypto_miner",
        "severity": WorkloadSeverity.HIGH,
        "process": "xmrig",
        "syscall": "connect",
        "container_escape": False,
        "description": (
            "Crypto-mining process xmrig detected connecting to mining pool stratum+tcp"
        ),
    },
    {
        "anomaly_type": "reverse_shell",
        "severity": WorkloadSeverity.CRITICAL,
        "process": "/bin/bash",
        "syscall": "connect",
        "container_escape": False,
        "description": ("Reverse shell detected: bash process opening outbound TCP to external IP"),
    },
    {
        "anomaly_type": "privilege_escalation",
        "severity": WorkloadSeverity.HIGH,
        "process": "sudo",
        "syscall": "setuid",
        "container_escape": False,
        "description": ("Unexpected privilege escalation via setuid in non-privileged container"),
    },
    {
        "anomaly_type": "suspicious_network",
        "severity": WorkloadSeverity.MEDIUM,
        "process": "curl",
        "syscall": "connect",
        "container_escape": False,
        "description": ("Outbound HTTP request to known C2 domain from production workload"),
    },
    {
        "anomaly_type": "cgroup_breakout",
        "severity": WorkloadSeverity.CRITICAL,
        "process": "release_agent",
        "syscall": "write",
        "container_escape": True,
        "description": (
            "Cgroup release_agent exploit detected attempting host-level code execution"
        ),
    },
]

# ---------------------------------------------------------------
# Mock drift patterns
# ---------------------------------------------------------------
_DRIFT_PATTERNS: list[dict[str, Any]] = [
    {
        "file_path": "/usr/bin/sshd",
        "change_type": "binary_modified",
        "severity": WorkloadSeverity.CRITICAL,
        "description": ("SSH daemon binary modified — possible backdoor implant"),
    },
    {
        "file_path": "/etc/passwd",
        "change_type": "content_modified",
        "severity": WorkloadSeverity.HIGH,
        "description": ("Password file modified: new user account added with UID 0"),
    },
    {
        "file_path": "/etc/ld.so.preload",
        "change_type": "file_created",
        "severity": WorkloadSeverity.CRITICAL,
        "description": ("ld.so.preload created — library preloading rootkit indicator"),
    },
    {
        "file_path": "/usr/lib/libcrypto.so.1.1",
        "change_type": "binary_modified",
        "severity": WorkloadSeverity.HIGH,
        "description": ("OpenSSL library modified — possible supply chain compromise"),
    },
    {
        "file_path": "/etc/crontab",
        "change_type": "content_modified",
        "severity": WorkloadSeverity.MEDIUM,
        "description": ("Crontab modified: new persistence mechanism scheduled"),
    },
]

# ---------------------------------------------------------------
# Mock vulnerability data
# ---------------------------------------------------------------
_VULN_DATA: list[dict[str, Any]] = [
    {
        "cve_id": "CVE-2024-21626",
        "package_name": "runc",
        "installed_version": "1.1.9",
        "fixed_version": "1.1.12",
        "severity": WorkloadSeverity.CRITICAL,
        "cvss_score": 8.6,
        "exploitable": True,
        "description": ("runc container breakout via leaked file descriptor (Leaky Vessels)"),
    },
    {
        "cve_id": "CVE-2024-3094",
        "package_name": "xz-utils",
        "installed_version": "5.6.0",
        "fixed_version": "5.6.2",
        "severity": WorkloadSeverity.CRITICAL,
        "cvss_score": 10.0,
        "exploitable": True,
        "description": ("XZ Utils backdoor — supply chain compromise in liblzma"),
    },
    {
        "cve_id": "CVE-2023-44487",
        "package_name": "golang",
        "installed_version": "1.20.8",
        "fixed_version": "1.21.3",
        "severity": WorkloadSeverity.HIGH,
        "cvss_score": 7.5,
        "exploitable": True,
        "description": ("HTTP/2 Rapid Reset DDoS attack vulnerability"),
    },
    {
        "cve_id": "CVE-2023-38545",
        "package_name": "curl",
        "installed_version": "8.3.0",
        "fixed_version": "8.4.0",
        "severity": WorkloadSeverity.HIGH,
        "cvss_score": 7.5,
        "exploitable": False,
        "description": ("SOCKS5 heap-based buffer overflow in curl"),
    },
    {
        "cve_id": "CVE-2023-4911",
        "package_name": "glibc",
        "installed_version": "2.37",
        "fixed_version": "2.38",
        "severity": WorkloadSeverity.HIGH,
        "cvss_score": 7.8,
        "exploitable": True,
        "description": ("Looney Tunables — glibc buffer overflow in ld.so"),
    },
    {
        "cve_id": "CVE-2023-32233",
        "package_name": "linux-kernel",
        "installed_version": "6.2.0",
        "fixed_version": "6.3.2",
        "severity": WorkloadSeverity.MEDIUM,
        "cvss_score": 6.7,
        "exploitable": False,
        "description": ("Netfilter nf_tables use-after-free privilege escalation"),
    },
]


class CloudWorkloadProtectorToolkit:
    """Toolkit for cloud workload protection operations."""

    def __init__(
        self,
        runtime_client: Any | None = None,
        vuln_db: Any | None = None,
    ) -> None:
        self._runtime_client = runtime_client
        self._vuln_db = vuln_db
        logger.info("cwp_toolkit.init")

    async def scan_workloads(
        self,
        tenant_id: str,
    ) -> list[WorkloadInventory]:
        """Scan and inventory running workloads."""
        logger.info(
            "cwp_toolkit.scan_workloads",
            tenant_id=tenant_id,
        )

        workloads: list[WorkloadInventory] = []
        for w in _MOCK_WORKLOADS:
            wl = WorkloadInventory(
                id=str(uuid.uuid4())[:8],
                tenant_id=tenant_id,
                workload_type=w["workload_type"],
                name=w["name"],
                namespace=w["namespace"],
                image=w["image"],
                host=w["host"],
                region=w["region"],
                cloud_provider=w["cloud_provider"],
                privileged=w.get("privileged", False),
                ports=w.get("ports", []),
                labels=w.get("labels", {}),
            )
            workloads.append(wl)
        return workloads

    async def detect_anomalies(
        self,
        workloads: list[WorkloadInventory],
    ) -> list[RuntimeAnomaly]:
        """Detect runtime anomalies across workloads."""
        logger.info(
            "cwp_toolkit.detect_anomalies",
            workload_count=len(workloads),
        )

        anomalies: list[RuntimeAnomaly] = []
        for wl in workloads:
            n = random.randint(0, 2)  # noqa: S311
            chosen = random.sample(  # noqa: S311
                _ANOMALY_PATTERNS,
                min(n, len(_ANOMALY_PATTERNS)),
            )
            for pattern in chosen:
                anomaly = RuntimeAnomaly(
                    id=str(uuid.uuid4())[:8],
                    workload_id=wl.id,
                    anomaly_type=pattern["anomaly_type"],
                    severity=pattern["severity"],
                    description=pattern["description"],
                    process=pattern["process"],
                    syscall=pattern["syscall"],
                    container_escape=pattern["container_escape"],
                )
                anomalies.append(anomaly)
        return anomalies

    async def analyze_drift(
        self,
        workloads: list[WorkloadInventory],
    ) -> list[DriftFinding]:
        """Analyze file integrity drift on workloads."""
        logger.info(
            "cwp_toolkit.analyze_drift",
            workload_count=len(workloads),
        )

        findings: list[DriftFinding] = []
        for wl in workloads:
            if wl.workload_type == WorkloadType.SERVERLESS:
                continue
            n = random.randint(0, 2)  # noqa: S311
            chosen = random.sample(  # noqa: S311
                _DRIFT_PATTERNS,
                min(n, len(_DRIFT_PATTERNS)),
            )
            for pattern in chosen:
                expected = hashlib.sha256(pattern["file_path"].encode()).hexdigest()[:16]
                actual = hashlib.sha256(f"{pattern['file_path']}-mod".encode()).hexdigest()[:16]
                finding = DriftFinding(
                    id=str(uuid.uuid4())[:8],
                    workload_id=wl.id,
                    file_path=pattern["file_path"],
                    change_type=pattern["change_type"],
                    severity=pattern["severity"],
                    expected_hash=expected,
                    actual_hash=actual,
                    description=pattern["description"],
                )
                findings.append(finding)
        return findings

    async def assess_vulnerabilities(
        self,
        workloads: list[WorkloadInventory],
    ) -> list[VulnerabilityFinding]:
        """Assess vulnerabilities in workload images."""
        logger.info(
            "cwp_toolkit.assess_vulnerabilities",
            workload_count=len(workloads),
        )

        findings: list[VulnerabilityFinding] = []
        for wl in workloads:
            n = random.randint(1, 3)  # noqa: S311
            chosen = random.sample(  # noqa: S311
                _VULN_DATA,
                min(n, len(_VULN_DATA)),
            )
            for vuln in chosen:
                finding = VulnerabilityFinding(
                    id=str(uuid.uuid4())[:8],
                    workload_id=wl.id,
                    cve_id=vuln["cve_id"],
                    package_name=vuln["package_name"],
                    installed_version=vuln["installed_version"],
                    fixed_version=vuln["fixed_version"],
                    severity=vuln["severity"],
                    cvss_score=vuln["cvss_score"],
                    exploitable=vuln["exploitable"],
                    description=vuln["description"],
                )
                findings.append(finding)
        return findings

    async def contain_threats(
        self,
        anomalies: list[RuntimeAnomaly],
        vulns: list[VulnerabilityFinding],
    ) -> list[ContainmentAction]:
        """Contain threats from anomalies and vulns."""
        logger.info(
            "cwp_toolkit.contain_threats",
            anomaly_count=len(anomalies),
            vuln_count=len(vulns),
        )

        actions: list[ContainmentAction] = []

        # Contain critical/high anomalies
        for anomaly in anomalies:
            if anomaly.severity not in (
                WorkloadSeverity.CRITICAL,
                WorkloadSeverity.HIGH,
            ):
                continue
            if anomaly.container_escape:
                action = ContainmentAction(
                    id=str(uuid.uuid4())[:8],
                    workload_id=anomaly.workload_id,
                    action_type="isolate_workload",
                    target=anomaly.workload_id,
                    description=(f"Isolate workload due to {anomaly.anomaly_type}"),
                    applied=True,
                    success=random.random() > 0.1,  # noqa: S311
                    rollback_available=True,
                )
            else:
                action = ContainmentAction(
                    id=str(uuid.uuid4())[:8],
                    workload_id=anomaly.workload_id,
                    action_type="kill_process",
                    target=anomaly.process,
                    description=(f"Kill malicious process {anomaly.process}"),
                    applied=True,
                    success=random.random() > 0.05,  # noqa: S311
                    rollback_available=False,
                )
            actions.append(action)

        # Quarantine images with critical vulns
        seen: set[str] = set()
        for vuln in vulns:
            if (
                vuln.severity == WorkloadSeverity.CRITICAL
                and vuln.exploitable
                and vuln.workload_id not in seen
            ):
                seen.add(vuln.workload_id)
                action = ContainmentAction(
                    id=str(uuid.uuid4())[:8],
                    workload_id=vuln.workload_id,
                    action_type="quarantine_image",
                    target=vuln.cve_id,
                    description=(f"Quarantine image for exploitable {vuln.cve_id}"),
                    applied=True,
                    success=True,
                    rollback_available=True,
                )
                actions.append(action)

        return actions
