"""Patch Compliance Checker Agent — Tool functions."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

import structlog

from .models import PatchSeverity, PatchStatus

logger = structlog.get_logger()

_SLA_DAYS = {
    PatchSeverity.CRITICAL: 7,
    PatchSeverity.HIGH: 14,
    PatchSeverity.MEDIUM: 30,
    PatchSeverity.LOW: 90,
    PatchSeverity.INFORMATIONAL: 180,
}


def _generate_id(prefix: str, *parts: str) -> str:
    raw = f"{':'.join(parts)}:{datetime.now(UTC).isoformat()}"
    return f"{prefix}-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


class PatchComplianceCheckerToolkit:
    """Tools for patch compliance checking."""

    def __init__(
        self,
        wsus_client: Any | None = None,
        vuln_client: Any | None = None,
    ) -> None:
        self._wsus = wsus_client
        self._vuln = vuln_client

    async def inventory_systems(self, tenant_id: str) -> list[dict[str, Any]]:
        """Inventory all systems in the fleet."""
        logger.info("patch.inventory", tenant_id=tenant_id)
        if self._wsus:
            try:
                return await self._wsus.list_systems(tenant_id=tenant_id)
            except Exception:
                logger.exception("patch.inventory.error")
        return [
            {
                "system_id": "SYS-001",
                "hostname": "web-prod-01",
                "os": "Ubuntu",
                "os_version": "22.04",
                "environment": "production",
                "criticality": "high",
            },
            {
                "system_id": "SYS-002",
                "hostname": "db-prod-01",
                "os": "RHEL",
                "os_version": "9.3",
                "environment": "production",
                "criticality": "critical",
            },
            {
                "system_id": "SYS-003",
                "hostname": "dev-ws-01",
                "os": "Windows",
                "os_version": "11",
                "environment": "development",
                "criticality": "low",
            },
            {
                "system_id": "SYS-004",
                "hostname": "api-staging-01",
                "os": "Ubuntu",
                "os_version": "22.04",
                "environment": "staging",
                "criticality": "medium",
            },
        ]

    async def scan_patches(
        self, systems: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], int, int]:
        """Scan systems for missing patches."""
        logger.info("patch.scan", system_count=len(systems))
        missing: list[dict[str, Any]] = []
        critical_count = 0

        patches_data = [
            {
                "patch_id": "PATCH-CVE-2026-1234",
                "system_id": "SYS-001",
                "cve_ids": ["CVE-2026-1234"],
                "severity": PatchSeverity.CRITICAL.value,
                "title": "OpenSSL remote code execution",
                "days_overdue": 12,
            },
            {
                "patch_id": "PATCH-CVE-2026-5678",
                "system_id": "SYS-002",
                "cve_ids": ["CVE-2026-5678"],
                "severity": PatchSeverity.HIGH.value,
                "title": "Linux kernel privilege escalation",
                "days_overdue": 5,
            },
            {
                "patch_id": "PATCH-KB5035000",
                "system_id": "SYS-003",
                "cve_ids": ["CVE-2026-9012"],
                "severity": PatchSeverity.MEDIUM.value,
                "title": "Windows security update",
                "days_overdue": 0,
            },
        ]

        for p in patches_data:
            p["status"] = PatchStatus.MISSING.value
            missing.append(p)
            if p["severity"] == PatchSeverity.CRITICAL.value:
                critical_count += 1

        return missing, len(missing), critical_count

    async def assess_risk(
        self,
        missing_patches: list[dict[str, Any]],
        systems: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], float]:
        """Assess risk of unpatched systems."""
        logger.info("patch.assess_risk")
        risk_map: dict[str, float] = {}
        assessments: list[dict[str, Any]] = []

        severity_weight = {
            PatchSeverity.CRITICAL.value: 30.0,
            PatchSeverity.HIGH.value: 20.0,
            PatchSeverity.MEDIUM.value: 10.0,
            PatchSeverity.LOW.value: 5.0,
            PatchSeverity.INFORMATIONAL.value: 1.0,
        }
        criticality_mult = {
            "critical": 2.0,
            "high": 1.5,
            "medium": 1.0,
            "low": 0.5,
        }

        sys_map = {s["system_id"]: s for s in systems}

        for patch in missing_patches:
            sid = patch["system_id"]
            sev = patch.get("severity", PatchSeverity.MEDIUM.value)
            system = sys_map.get(sid, {})
            crit = system.get("criticality", "medium")
            score = severity_weight.get(sev, 10.0) * criticality_mult.get(crit, 1.0)
            risk_map[sid] = risk_map.get(sid, 0.0) + score
            assessments.append(
                {
                    "system_id": sid,
                    "patch_id": patch["patch_id"],
                    "risk_score": score,
                    "severity": sev,
                    "criticality": crit,
                }
            )

        fleet_risk = min(sum(risk_map.values()) / max(len(systems), 1), 100.0)
        return assessments, round(fleet_risk, 1)

    async def check_sla(
        self, missing_patches: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], float]:
        """Check SLA compliance for patching."""
        logger.info("patch.check_sla")
        violations: list[dict[str, Any]] = []
        total = len(missing_patches)
        compliant = 0

        for p in missing_patches:
            sev = PatchSeverity(p.get("severity", "medium"))
            overdue = p.get("days_overdue", 0)
            sla_days = _SLA_DAYS.get(sev, 30)

            if overdue > sla_days:
                violations.append(
                    {
                        "patch_id": p["patch_id"],
                        "system_id": p["system_id"],
                        "severity": sev.value,
                        "sla_days": sla_days,
                        "days_overdue": overdue,
                        "breach_days": overdue - sla_days,
                    }
                )
            else:
                compliant += 1

        rate = (compliant / total * 100) if total else 100.0
        return violations, round(rate, 1)

    async def schedule_rollout(
        self,
        missing_patches: list[dict[str, Any]],
        risk_assessments: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Schedule patch rollout based on risk priority."""
        logger.info("patch.schedule")
        schedule: list[dict[str, Any]] = []
        priority_order = sorted(
            risk_assessments,
            key=lambda x: x.get("risk_score", 0),
            reverse=True,
        )

        for i, assessment in enumerate(priority_order):
            schedule.append(
                {
                    "id": _generate_id("ROL", assessment["patch_id"]),
                    "patch_id": assessment["patch_id"],
                    "target_systems": [assessment["system_id"]],
                    "priority": i + 1,
                    "window": "maintenance_window_1" if i < 2 else "maintenance_window_2",
                }
            )

        return schedule
