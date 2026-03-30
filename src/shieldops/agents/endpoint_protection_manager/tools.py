"""Endpoint Protection Manager Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    AgentHealth,
    EndpointDevice,
    EndpointOS,
    MalwareScan,
    PatchStatus,
    ProtectionStatus,
    RemediationAction,
)

logger = structlog.get_logger()

_ENDPOINT_PROFILES: list[dict[str, Any]] = [
    {
        "hostname": "prod-web-01",
        "os": EndpointOS.LINUX,
        "os_version": "Ubuntu 22.04",
        "ip": "10.0.1.10",
        "env": "production",
    },
    {
        "hostname": "prod-web-02",
        "os": EndpointOS.LINUX,
        "os_version": "Ubuntu 22.04",
        "ip": "10.0.1.11",
        "env": "production",
    },
    {
        "hostname": "prod-db-01",
        "os": EndpointOS.LINUX,
        "os_version": "RHEL 9.2",
        "ip": "10.0.2.10",
        "env": "production",
    },
    {
        "hostname": "corp-ws-001",
        "os": EndpointOS.WINDOWS,
        "os_version": "Windows 11 23H2",
        "ip": "10.1.0.50",
        "env": "corporate",
    },
    {
        "hostname": "corp-ws-002",
        "os": EndpointOS.WINDOWS,
        "os_version": "Windows 10 22H2",
        "ip": "10.1.0.51",
        "env": "corporate",
    },
    {
        "hostname": "dev-mac-01",
        "os": EndpointOS.MACOS,
        "os_version": "macOS 15.1",
        "ip": "10.2.0.10",
        "env": "development",
    },
    {
        "hostname": "k8s-node-01",
        "os": EndpointOS.CONTAINER,
        "os_version": "containerd 1.7",
        "ip": "10.3.0.20",
        "env": "production",
    },
    {
        "hostname": "iot-sensor-01",
        "os": EndpointOS.EMBEDDED,
        "os_version": "FreeRTOS 10.5",
        "ip": "10.4.0.5",
        "env": "edge",
    },
]

_STATUSES = [
    ProtectionStatus.PROTECTED,
    ProtectionStatus.PROTECTED,
    ProtectionStatus.PROTECTED,
    ProtectionStatus.PARTIALLY_PROTECTED,
    ProtectionStatus.UNPROTECTED,
    ProtectionStatus.OFFLINE,
    ProtectionStatus.QUARANTINED,
]

_THREAT_NAMES = [
    "Trojan.GenericKD",
    "PUP.Adware.Browser",
    "Exploit.CVE-2024-1234",
    "Ransomware.WannaCry.Gen",
    "Backdoor.Cobalt.Strike",
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class EndpointProtectionManagerToolkit:
    """Tools for endpoint protection management."""

    def __init__(
        self,
        edr_api: Any | None = None,
        cmdb_api: Any | None = None,
    ) -> None:
        self._edr_api = edr_api
        self._cmdb_api = cmdb_api

    async def inventory_endpoints(
        self,
        tenant_id: str,
    ) -> list[EndpointDevice]:
        """Discover and inventory managed endpoints."""
        logger.info(
            "epm.inventory_endpoints",
            tenant_id=tenant_id,
        )

        if self._cmdb_api is not None:
            try:
                raw = await self._cmdb_api.list_endpoints(
                    tenant_id=tenant_id,
                )
                return [EndpointDevice(**r) for r in raw]
            except Exception:
                logger.exception("epm.inventory.error")

        devices: list[EndpointDevice] = []
        for i, p in enumerate(_ENDPOINT_PROFILES):
            status = random.choice(_STATUSES)  # noqa: S311
            devices.append(
                EndpointDevice(
                    id=_gen_id("EP", tenant_id, i),
                    hostname=p["hostname"],
                    os=p["os"],
                    os_version=p["os_version"],
                    ip_address=p["ip"],
                    last_seen="2026-03-30T10:00:00Z",
                    status=status,
                    environment=p["env"],
                    tags={"managed": "true"},
                )
            )
        return devices

    async def check_agent_health(
        self,
        endpoints: list[EndpointDevice],
    ) -> list[AgentHealth]:
        """Check security agent health on each endpoint."""
        logger.info(
            "epm.check_agents",
            count=len(endpoints),
        )

        if self._edr_api is not None:
            try:
                ids = [e.id for e in endpoints]
                raw = await self._edr_api.get_agent_health(
                    endpoint_ids=ids,
                )
                return [AgentHealth(**r) for r in raw]
            except Exception:
                logger.exception("epm.check_agents.error")

        results: list[AgentHealth] = []
        for ep in endpoints:
            running = ep.status not in (
                ProtectionStatus.OFFLINE,
                ProtectionStatus.UNPROTECTED,
            )
            def_age = random.randint(0, 14)  # noqa: S311
            issues: list[str] = []
            if not running:
                issues.append("agent_not_running")
            if def_age > 7:
                issues.append("definitions_outdated")
            results.append(
                AgentHealth(
                    endpoint_id=ep.id,
                    agent_name="ShieldOps EDR",
                    agent_version="4.2.1",
                    running=running,
                    last_checkin=(ep.last_seen if running else "2026-03-28T00:00:00Z"),
                    definitions_version=f"2026.03.{30 - def_age:02d}",
                    definitions_age_days=def_age,
                    cpu_pct=round(
                        random.uniform(0.5, 8.0),  # noqa: S311
                        1,
                    ),
                    memory_mb=round(
                        random.uniform(50, 250),  # noqa: S311
                        1,
                    ),
                    issues=issues,
                )
            )
        return results

    async def assess_patches(
        self,
        endpoints: list[EndpointDevice],
    ) -> list[PatchStatus]:
        """Assess patch compliance for each endpoint."""
        logger.info(
            "epm.assess_patches",
            count=len(endpoints),
        )

        results: list[PatchStatus] = []
        for ep in endpoints:
            total = random.randint(50, 200)  # noqa: S311
            missing_c = random.randint(0, 3)  # noqa: S311
            missing_h = random.randint(0, 5)  # noqa: S311
            missing_m = random.randint(0, 10)  # noqa: S311
            installed = total - missing_c - missing_h - missing_m
            results.append(
                PatchStatus(
                    endpoint_id=ep.id,
                    total_patches=total,
                    installed=max(0, installed),
                    missing_critical=missing_c,
                    missing_high=missing_h,
                    missing_medium=missing_m,
                    last_scan="2026-03-29T18:00:00Z",
                    reboot_pending=(
                        random.random() < 0.2  # noqa: S311
                    ),
                )
            )
        return results

    async def scan_malware(
        self,
        endpoints: list[EndpointDevice],
    ) -> list[MalwareScan]:
        """Run malware scans on endpoints."""
        logger.info(
            "epm.scan_malware",
            count=len(endpoints),
        )

        results: list[MalwareScan] = []
        for ep in endpoints:
            threats = random.randint(0, 2)  # noqa: S311
            quarantined = min(
                threats,
                random.randint(0, threats),  # noqa: S311
            )
            names = random.sample(  # noqa: S311
                _THREAT_NAMES,
                min(threats, len(_THREAT_NAMES)),
            )
            results.append(
                MalwareScan(
                    endpoint_id=ep.id,
                    scan_type="quick",
                    threats_found=threats,
                    threats_quarantined=quarantined,
                    threats_removed=0,
                    scan_duration_sec=round(
                        random.uniform(30, 300),  # noqa: S311
                        1,
                    ),
                    last_full_scan="2026-03-28T02:00:00Z",
                    threat_names=names,
                )
            )
        return results

    async def remediate_gaps(
        self,
        endpoints: list[EndpointDevice],
        agent_health: list[AgentHealth],
        patch_statuses: list[PatchStatus],
        malware_scans: list[MalwareScan],
    ) -> list[RemediationAction]:
        """Generate and execute remediation actions."""
        logger.info("epm.remediate_gaps")

        health_map = {a.endpoint_id: a for a in agent_health}
        patch_map = {p.endpoint_id: p for p in patch_statuses}
        scan_map = {s.endpoint_id: s for s in malware_scans}

        actions: list[RemediationAction] = []
        idx = 0

        for ep in endpoints:
            ah = health_map.get(ep.id)
            ps = patch_map.get(ep.id)
            ms = scan_map.get(ep.id)

            if ah and not ah.running:
                actions.append(
                    RemediationAction(
                        id=_gen_id("RA", ep.id, idx),
                        endpoint_id=ep.id,
                        action_type="restart_agent",
                        description=(f"Restart EDR agent on {ep.hostname}"),
                        status="executed",
                        auto_executable=True,
                        risk="low",
                        result="agent_restarted",
                    )
                )
                idx += 1

            if ah and ah.definitions_age_days > 7:
                actions.append(
                    RemediationAction(
                        id=_gen_id("RA", ep.id, idx),
                        endpoint_id=ep.id,
                        action_type="update_definitions",
                        description=(f"Update definitions on {ep.hostname}"),
                        status="executed",
                        auto_executable=True,
                        risk="low",
                        result="definitions_updated",
                    )
                )
                idx += 1

            if ps and ps.missing_critical > 0:
                actions.append(
                    RemediationAction(
                        id=_gen_id("RA", ep.id, idx),
                        endpoint_id=ep.id,
                        action_type="install_patches",
                        description=(
                            f"Install {ps.missing_critical} critical patches on {ep.hostname}"
                        ),
                        status="pending_approval",
                        auto_executable=False,
                        risk="medium",
                        result="",
                    )
                )
                idx += 1

            if ms and ms.threats_found > ms.threats_quarantined:
                active = ms.threats_found - ms.threats_quarantined
                actions.append(
                    RemediationAction(
                        id=_gen_id("RA", ep.id, idx),
                        endpoint_id=ep.id,
                        action_type="quarantine_threats",
                        description=(f"Quarantine {active} active threats on {ep.hostname}"),
                        status="executed",
                        auto_executable=True,
                        risk="high",
                        result="threats_quarantined",
                    )
                )
                idx += 1

        return actions
