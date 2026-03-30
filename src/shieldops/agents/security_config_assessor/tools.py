"""Security Config Assessor Agent — Tool functions for config scanning and remediation."""

from __future__ import annotations

import hashlib
import random
import time
import uuid
from typing import Any

import structlog

from .models import (
    BenchmarkResult,
    BenchmarkType,
    ComplianceLevel,
    ConfigDrift,
    ConfigScan,
    RemediationScript,
    SystemInventory,
)

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# CIS controls per benchmark type
# ---------------------------------------------------------------------------
CIS_CONTROLS: dict[str, list[dict[str, Any]]] = {
    "cis_aws": [
        {
            "control_id": "CIS-AWS-1.4",
            "control_name": "Ensure root MFA is enabled",
            "config_path": "/iam/root-mfa",
            "expected": "enabled",
            "severity": "critical",
            "level": "level_1",
            "remediation": ("aws iam enable-mfa-device --user-name root"),
            "auto_fixable": False,
        },
        {
            "control_id": "CIS-AWS-2.1.1",
            "control_name": "Ensure S3 bucket encryption",
            "config_path": "/s3/default-encryption",
            "expected": "AES256|aws:kms",
            "severity": "high",
            "level": "level_1",
            "remediation": (
                "aws s3api put-bucket-encryption"
                " --bucket $BUCKET"
                " --server-side-encryption-configuration ..."
            ),
            "auto_fixable": True,
        },
        {
            "control_id": "CIS-AWS-3.1",
            "control_name": "Ensure CloudTrail is enabled",
            "config_path": "/cloudtrail/multi-region",
            "expected": "true",
            "severity": "high",
            "level": "level_1",
            "remediation": ("aws cloudtrail create-trail --name shieldops-trail --is-multi-region"),
            "auto_fixable": True,
        },
    ],
    "cis_k8s": [
        {
            "control_id": "CIS-K8S-5.1.1",
            "control_name": "Ensure RBAC is enabled",
            "config_path": "/apiserver/authorization-mode",
            "expected": "RBAC",
            "severity": "critical",
            "level": "level_1",
            "remediation": ("kube-apiserver --authorization-mode=RBAC"),
            "auto_fixable": False,
        },
        {
            "control_id": "CIS-K8S-5.2.2",
            "control_name": "Ensure pods not privileged",
            "config_path": "/pod/security-context",
            "expected": "privileged=false",
            "severity": "high",
            "level": "level_1",
            "remediation": (
                'kubectl patch pod $POD -p \'{"spec":{"securityContext":{"privileged":false}}}\''
            ),
            "auto_fixable": True,
        },
    ],
    "cis_linux": [
        {
            "control_id": "CIS-LNX-1.1.1",
            "control_name": "Ensure /tmp is a separate partition",
            "config_path": "/etc/fstab",
            "expected": "/tmp partition present",  # noqa: S108  # nosec B108
            "severity": "medium",
            "level": "level_1",
            "remediation": (  # nosec B108
                "echo 'tmpfs /tmp tmpfs defaults,noexec,nosuid 0 0' >> /etc/fstab && mount -a"
            ),
            "auto_fixable": True,
        },
        {
            "control_id": "CIS-LNX-5.2.1",
            "control_name": "Ensure SSH PermitRootLogin is no",
            "config_path": "/etc/ssh/sshd_config",
            "expected": "PermitRootLogin no",
            "severity": "critical",
            "level": "level_1",
            "remediation": (
                "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/'"
                " /etc/ssh/sshd_config && systemctl restart sshd"
            ),
            "auto_fixable": True,
        },
    ],
    "cis_docker": [
        {
            "control_id": "CIS-DKR-2.1",
            "control_name": "Ensure network traffic restricted",
            "config_path": "/etc/docker/daemon.json",
            "expected": "icc=false",
            "severity": "high",
            "level": "level_1",
            "remediation": (
                "echo '{\"icc\": false}' > /etc/docker/daemon.json && systemctl restart docker"
            ),
            "auto_fixable": True,
        },
        {
            "control_id": "CIS-DKR-4.1",
            "control_name": "Ensure container user is non-root",
            "config_path": "Dockerfile",
            "expected": "USER non-root",
            "severity": "high",
            "level": "level_1",
            "remediation": ("Add 'USER appuser' to Dockerfile"),
            "auto_fixable": False,
        },
    ],
    "cis_gcp": [
        {
            "control_id": "CIS-GCP-1.4",
            "control_name": "Ensure SA key rotation 90 days",
            "config_path": "/iam/service-account-keys",
            "expected": "rotation_period<=90d",
            "severity": "high",
            "level": "level_1",
            "remediation": ("gcloud iam service-accounts keys delete $KEY_ID --iam-account=$SA"),
            "auto_fixable": True,
        },
    ],
    "cis_azure": [
        {
            "control_id": "CIS-AZ-1.3",
            "control_name": "Ensure MFA for privileged users",
            "config_path": "/aad/conditional-access",
            "expected": "mfa_enforced=true",
            "severity": "critical",
            "level": "level_1",
            "remediation": ("az ad conditional-access policy create --grant-controls mfa"),
            "auto_fixable": False,
        },
    ],
}

# Simulated system templates per benchmark
_SYSTEM_TEMPLATES: dict[str, list[dict[str, str]]] = {
    "cis_aws": [
        {"hostname": "aws-account", "platform": "aws"},
    ],
    "cis_gcp": [
        {"hostname": "gcp-project", "platform": "gcp"},
    ],
    "cis_azure": [
        {"hostname": "azure-subscription", "platform": "azure"},
    ],
    "cis_k8s": [
        {"hostname": "k8s-cluster", "platform": "kubernetes"},
    ],
    "cis_linux": [
        {"hostname": "linux-server", "platform": "linux"},
    ],
    "cis_docker": [
        {"hostname": "docker-host", "platform": "docker"},
    ],
}

_REGIONS: dict[str, list[str]] = {
    "aws": ["us-east-1", "us-west-2", "eu-west-1"],
    "gcp": ["us-central1", "europe-west1"],
    "azure": ["eastus", "westeurope"],
    "kubernetes": ["default-cluster"],
    "linux": ["datacenter-1", "datacenter-2"],
    "docker": ["docker-host-1"],
}


def _system_hash(platform: str, idx: int) -> str:
    """Deterministic system id."""
    raw = f"{platform}-system-{idx}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


class SecurityConfigAssessorToolkit:
    """Tools for CIS benchmark assessment and remediation script generation."""

    def __init__(
        self,
        infra_clients: Any | None = None,
        benchmark_db: Any | None = None,
    ) -> None:
        self._infra_clients = infra_clients
        self._benchmark_db = benchmark_db

    # ----------------------------------------------------------
    # 1. Inventory systems
    # ----------------------------------------------------------
    async def inventory_systems(
        self,
        tenant_id: str,
        benchmarks: list[str],
    ) -> list[SystemInventory]:
        """Enumerate target systems for the requested benchmarks."""
        logger.info(
            "sca.inventory_systems",
            tenant_id=tenant_id,
            benchmarks=benchmarks,
        )

        if self._infra_clients is not None:
            try:
                raw = await self._infra_clients.discover(
                    tenant_id=tenant_id,
                    benchmarks=benchmarks,
                )
                return [SystemInventory(**r) for r in raw]
            except Exception:
                logger.exception("sca.inventory.client_error")

        systems: list[SystemInventory] = []
        for bm_key in benchmarks:
            templates = _SYSTEM_TEMPLATES.get(bm_key, [])
            platform = templates[0]["platform"] if templates else "unknown"
            regions = _REGIONS.get(platform, ["global"])
            count = random.randint(2, 5)  # noqa: S311
            for idx in range(count):
                sid = _system_hash(platform, idx)
                systems.append(
                    SystemInventory(
                        id=f"sys-{sid}",
                        hostname=(f"{platform}-{sid}"),
                        platform=platform,
                        benchmark=BenchmarkType(bm_key),
                        region=random.choice(regions),  # noqa: S311
                        tags={
                            "env": random.choice(  # noqa: S311
                                ["prod", "staging", "dev"],
                            ),
                        },
                        reachable=random.random() > 0.1,  # noqa: S311
                    )
                )

        logger.info(
            "sca.inventory_systems.done",
            system_count=len(systems),
        )
        return systems

    # ----------------------------------------------------------
    # 2. Scan configurations
    # ----------------------------------------------------------
    async def scan_configs(
        self,
        systems: list[SystemInventory],
    ) -> list[ConfigScan]:
        """Collect configuration items from target systems."""
        logger.info(
            "sca.scan_configs",
            system_count=len(systems),
        )

        scans: list[ConfigScan] = []
        for sys in systems:
            if not sys.reachable:
                continue
            controls = CIS_CONTROLS.get(
                sys.benchmark.value,
                [],
            )
            for ctrl in controls:
                compliant = random.random() > 0.35  # noqa: S311
                actual = ctrl["expected"] if compliant else "non_compliant"
                scans.append(
                    ConfigScan(
                        id=str(uuid.uuid4())[:8],
                        system_id=sys.id,
                        config_path=ctrl["config_path"],
                        current_value=actual,
                        expected_value=ctrl["expected"],
                        compliant=compliant,
                        category=ctrl["control_id"],
                    )
                )

        logger.info(
            "sca.scan_configs.done",
            scan_count=len(scans),
        )
        return scans

    # ----------------------------------------------------------
    # 3. Benchmark check
    # ----------------------------------------------------------
    async def benchmark_check(
        self,
        systems: list[SystemInventory],
        scans: list[ConfigScan],
        compliance_level: str,
    ) -> list[BenchmarkResult]:
        """Evaluate CIS controls against collected configs."""
        logger.info(
            "sca.benchmark_check",
            scan_count=len(scans),
            level=compliance_level,
        )

        if self._benchmark_db is not None:
            try:
                raw = await self._benchmark_db.evaluate(
                    scans=[s.model_dump() for s in scans],
                    level=compliance_level,
                )
                return [BenchmarkResult(**b) for b in raw]
            except Exception:
                logger.exception("sca.benchmark_check.db_error")

        scan_by_system: dict[str, list[ConfigScan]] = {}
        for s in scans:
            scan_by_system.setdefault(s.system_id, []).append(s)

        results: list[BenchmarkResult] = []
        for sys in systems:
            if not sys.reachable:
                continue
            controls = CIS_CONTROLS.get(
                sys.benchmark.value,
                [],
            )
            sys_scans = scan_by_system.get(sys.id, [])
            scan_map = {sc.category: sc for sc in sys_scans}

            for ctrl in controls:
                if compliance_level == ComplianceLevel.LEVEL_1.value and ctrl["level"] == "level_2":
                    continue

                sc = scan_map.get(ctrl["control_id"])
                status = (
                    "pass"
                    if (sc and sc.compliant)
                    else (
                        random.choice(  # noqa: S311
                            ["fail", "fail", "warn"],
                        )
                    )
                )
                results.append(
                    BenchmarkResult(
                        id=str(uuid.uuid4())[:8],
                        benchmark=sys.benchmark,
                        level=ComplianceLevel(compliance_level),
                        control_id=ctrl["control_id"],
                        control_name=ctrl["control_name"],
                        system_id=sys.id,
                        status=status,
                        severity=ctrl["severity"],
                        description=(f"{ctrl['control_name']} on {sys.hostname}"),
                        remediation_hint=ctrl["remediation"],
                    )
                )

        logger.info(
            "sca.benchmark_check.done",
            result_count=len(results),
        )
        return results

    # ----------------------------------------------------------
    # 4. Detect drift
    # ----------------------------------------------------------
    async def detect_drift(
        self,
        scans: list[ConfigScan],
        results: list[BenchmarkResult],
    ) -> list[ConfigDrift]:
        """Detect configuration drift from hardening baseline."""
        logger.info(
            "sca.detect_drift",
            scan_count=len(scans),
        )

        drifts: list[ConfigDrift] = []
        failing = {r.control_id: r for r in results if r.status != "pass"}

        for sc in scans:
            if sc.compliant:
                continue
            result = failing.get(sc.category)
            severity = result.severity if result else "medium"
            drifts.append(
                ConfigDrift(
                    id=str(uuid.uuid4())[:8],
                    system_id=sc.system_id,
                    control_id=sc.category,
                    config_path=sc.config_path,
                    baseline_value=sc.expected_value,
                    actual_value=sc.current_value,
                    drift_severity=severity,
                    first_seen=time.time(),
                )
            )

        logger.info(
            "sca.detect_drift.done",
            drift_count=len(drifts),
        )
        return drifts

    # ----------------------------------------------------------
    # 5. Generate remediation scripts
    # ----------------------------------------------------------
    async def generate_fixes(
        self,
        results: list[BenchmarkResult],
        drifts: list[ConfigDrift],
    ) -> list[RemediationScript]:
        """Generate remediation scripts for failing controls."""
        logger.info(
            "sca.generate_fixes",
            result_count=len(results),
            drift_count=len(drifts),
        )

        scripts: list[RemediationScript] = []
        seen: set[tuple[str, str]] = set()

        for r in results:
            if r.status == "pass":
                continue
            key = (r.system_id, r.control_id)
            if key in seen:
                continue
            seen.add(key)

            ctrl = self._lookup_control(
                r.benchmark.value,
                r.control_id,
            )
            auto_fixable = ctrl.get("auto_fixable", False) if ctrl else False
            hint = r.remediation_hint or (ctrl.get("remediation", "") if ctrl else "")

            script_body = (
                f"#!/bin/bash\n"
                f"# Remediation: {r.control_name}\n"
                f"# Control: {r.control_id}\n"
                f"set -euo pipefail\n\n"
                f"{hint}\n"
            )

            scripts.append(
                RemediationScript(
                    id=str(uuid.uuid4())[:8],
                    system_id=r.system_id,
                    control_id=r.control_id,
                    script_type="bash",
                    script_body=script_body,
                    description=(f"Fix {r.control_name}"),
                    reversible=auto_fixable,
                    risk_level=r.severity,
                )
            )

        logger.info(
            "sca.generate_fixes.done",
            script_count=len(scripts),
        )
        return scripts

    # ----------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------
    @staticmethod
    def _lookup_control(
        benchmark: str,
        control_id: str,
    ) -> dict[str, Any] | None:
        """Look up a control definition by benchmark and ID."""
        controls = CIS_CONTROLS.get(benchmark, [])
        for ctrl in controls:
            if ctrl["control_id"] == control_id:
                return ctrl  # type: ignore[no-any-return]
        return None
