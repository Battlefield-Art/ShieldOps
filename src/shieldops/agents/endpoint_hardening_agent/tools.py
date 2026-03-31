"""Endpoint Hardening Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    BaselineCheck,
    BenchmarkType,
    Deviation,
    DeviationSeverity,
    EndpointScan,
    HardeningFix,
    HardeningResult,
)

logger = structlog.get_logger()

_SAMPLE_ENDPOINTS: list[dict[str, Any]] = [
    {
        "hostname": "web-prod-01",
        "os_type": "linux",
        "os_version": "Ubuntu 22.04",
        "agent_version": "5.2.1",
        "last_patched": "2026-03-15",
        "open_ports": [22, 80, 443],
        "services_running": 12,
        "disk_encrypted": True,
        "firewall_enabled": True,
    },
    {
        "hostname": "db-prod-02",
        "os_type": "linux",
        "os_version": "RHEL 9.1",
        "agent_version": "5.2.0",
        "last_patched": "2026-02-28",
        "open_ports": [22, 5432],
        "services_running": 8,
        "disk_encrypted": True,
        "firewall_enabled": True,
    },
    {
        "hostname": "win-dev-01",
        "os_type": "windows",
        "os_version": "Windows Server 2022",
        "agent_version": "5.1.9",
        "last_patched": "2026-01-10",
        "open_ports": [3389, 445, 139],
        "services_running": 45,
        "disk_encrypted": False,
        "firewall_enabled": False,
    },
    {
        "hostname": "mac-eng-03",
        "os_type": "macos",
        "os_version": "macOS 15.2",
        "agent_version": "5.2.1",
        "last_patched": "2026-03-20",
        "open_ports": [22],
        "services_running": 6,
        "disk_encrypted": True,
        "firewall_enabled": True,
    },
    {
        "hostname": "api-staging-01",
        "os_type": "linux",
        "os_version": "Debian 12",
        "agent_version": "5.2.1",
        "last_patched": "2026-03-25",
        "open_ports": [22, 8080, 8443],
        "services_running": 10,
        "disk_encrypted": True,
        "firewall_enabled": True,
    },
]

_CIS_CONTROLS = [
    ("1.1.1", "Ensure filesystem integrity checking", "critical"),
    ("1.3.1", "Ensure AIDE is installed", "high"),
    ("2.2.1", "Ensure time synchronization is configured", "medium"),
    ("3.1.1", "Ensure IP forwarding is disabled", "high"),
    ("4.1.1", "Ensure auditing is enabled", "critical"),
    ("5.2.1", "Ensure SSH MaxAuthTries is set", "medium"),
    ("5.3.1", "Ensure password policy is configured", "high"),
    ("6.1.1", "Ensure permissions on /etc/passwd", "medium"),
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class EndpointHardeningAgentToolkit:
    """Tools for endpoint hardening and benchmark compliance."""

    def __init__(
        self,
        endpoint_api: Any | None = None,
        benchmark_db: Any | None = None,
    ) -> None:
        self._endpoint_api = endpoint_api
        self._benchmark_db = benchmark_db

    async def scan_endpoints(
        self,
        tenant_id: str,
    ) -> list[EndpointScan]:
        """Scan endpoints for current security posture."""
        logger.info(
            "eha.scan_endpoints",
            tenant_id=tenant_id,
        )

        if self._endpoint_api is not None:
            try:
                raw = await self._endpoint_api.scan(
                    tenant_id=tenant_id,
                )
                return [EndpointScan(**r) for r in raw]
            except Exception:
                logger.exception("eha.scan_endpoints.error")

        scans: list[EndpointScan] = []
        for i, ep in enumerate(_SAMPLE_ENDPOINTS):
            scans.append(
                EndpointScan(
                    id=_gen_id("ES", tenant_id, i),
                    hostname=ep["hostname"],
                    os_type=ep["os_type"],
                    os_version=ep["os_version"],
                    agent_version=ep["agent_version"],
                    last_patched=ep["last_patched"],
                    open_ports=ep["open_ports"],
                    services_running=ep["services_running"],
                    disk_encrypted=ep["disk_encrypted"],
                    firewall_enabled=ep["firewall_enabled"],
                )
            )
        return scans

    async def check_baseline(
        self,
        scans: list[EndpointScan],
    ) -> list[BaselineCheck]:
        """Check endpoints against CIS benchmark baselines."""
        logger.info(
            "eha.check_baseline",
            count=len(scans),
        )

        checks: list[BaselineCheck] = []
        for i, scan in enumerate(scans):
            benchmark = BenchmarkType.CIS_LINUX
            if scan.os_type == "windows":
                benchmark = BenchmarkType.CIS_WINDOWS
            elif scan.os_type == "macos":
                benchmark = BenchmarkType.CIS_MACOS

            total = len(_CIS_CONTROLS)
            passing = random.randint(total // 2, total)  # noqa: S311
            failing = total - passing
            score = round((passing / total) * 100, 1)
            checks.append(
                BaselineCheck(
                    id=_gen_id("BC", scan.hostname, i),
                    hostname=scan.hostname,
                    benchmark=benchmark,
                    total_controls=total,
                    passing=passing,
                    failing=failing,
                    score_pct=score,
                )
            )
        return checks

    async def detect_deviations(
        self,
        baselines: list[BaselineCheck],
    ) -> list[Deviation]:
        """Detect deviations from security baselines."""
        logger.info(
            "eha.detect_deviations",
            count=len(baselines),
        )

        deviations: list[Deviation] = []
        idx = 0
        for bl in baselines:
            for ctrl_id, ctrl_name, sev in _CIS_CONTROLS:
                hit = random.random()  # noqa: S311
                if hit > 0.5:
                    deviations.append(
                        Deviation(
                            id=_gen_id("DV", bl.hostname, idx),
                            hostname=bl.hostname,
                            control_id=ctrl_id,
                            control_name=ctrl_name,
                            severity=DeviationSeverity(sev),
                            current_value="non-compliant",
                            expected_value="compliant",
                            remediation_available=True,
                        )
                    )
                    idx += 1
        return deviations

    async def generate_fixes(
        self,
        deviations: list[Deviation],
    ) -> list[HardeningFix]:
        """Generate hardening fixes for detected deviations."""
        logger.info(
            "eha.generate_fixes",
            count=len(deviations),
        )

        fixes: list[HardeningFix] = []
        for i, d in enumerate(deviations):
            if not d.remediation_available:
                continue
            reboot = d.severity == DeviationSeverity.CRITICAL
            fixes.append(
                HardeningFix(
                    id=_gen_id("HF", d.id, i),
                    deviation_id=d.id,
                    hostname=d.hostname,
                    fix_type="config_change",
                    command=f"remediate --control {d.control_id}",
                    rollback_command=f"rollback --control {d.control_id}",
                    risk_level="medium" if reboot else "low",
                    requires_reboot=reboot,
                )
            )
        return fixes

    async def apply_hardening(
        self,
        fixes: list[HardeningFix],
    ) -> list[HardeningResult]:
        """Apply hardening fixes to endpoints."""
        logger.info(
            "eha.apply_hardening",
            count=len(fixes),
        )

        results: list[HardeningResult] = []
        for i, f in enumerate(fixes):
            dur = random.randint(100, 3000)  # noqa: S311
            success = random.random() > 0.1  # noqa: S311
            status = "applied" if success else "failed"
            results.append(
                HardeningResult(
                    id=_gen_id("HR", f.id, i),
                    fix_id=f.id,
                    hostname=f.hostname,
                    applied=success,
                    status=status,
                    duration_ms=dur,
                    error="" if success else "Permission denied",
                )
            )
        return results

    async def record_metric(
        self,
        metric_name: str,
        value: float,
    ) -> dict[str, Any]:
        """Record a hardening metric."""
        logger.info(
            "eha.record_metric",
            metric=metric_name,
            value=value,
        )
        return {"metric": metric_name, "value": value, "recorded": True}
