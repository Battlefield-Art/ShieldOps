"""Mobile Device Manager Agent — Tool functions."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

import structlog

from .models import DeviceAction

logger = structlog.get_logger()

_BLOCKED_APPS = {"TikTok", "WhatsApp Business", "Telegram", "Signal"}
_REQUIRED_APPS = {"Company Portal", "Authenticator", "MDM Agent"}


def _generate_id(prefix: str, *parts: str) -> str:
    raw = f"{':'.join(parts)}:{datetime.now(UTC).isoformat()}"
    return f"{prefix}-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


class MobileDeviceManagerToolkit:
    """Tools for mobile device management operations."""

    def __init__(
        self,
        mdm_client: Any | None = None,
        directory_client: Any | None = None,
    ) -> None:
        self._mdm = mdm_client
        self._directory = directory_client

    async def discover_devices(self, tenant_id: str) -> list[dict[str, Any]]:
        """Discover all mobile devices in the tenant."""
        logger.info("mdm.discover", tenant_id=tenant_id)
        if self._mdm:
            try:
                return await self._mdm.list_devices(tenant_id=tenant_id)
            except Exception:
                logger.exception("mdm.discover.error")
        return [
            {
                "device_id": "DEV-001",
                "name": "iPhone 15 Pro",
                "platform": "iOS",
                "os_version": "17.4",
                "owner": "alice@corp.com",
                "enrolled": True,
                "encrypted": True,
                "apps": ["Slack", "Authenticator"],
            },
            {
                "device_id": "DEV-002",
                "name": "Galaxy S24",
                "platform": "Android",
                "os_version": "14.0",
                "owner": "bob@corp.com",
                "enrolled": True,
                "encrypted": False,
                "apps": ["TikTok", "Slack"],
            },
            {
                "device_id": "DEV-003",
                "name": "Pixel 8",
                "platform": "Android",
                "os_version": "13.0",
                "owner": "charlie@corp.com",
                "enrolled": False,
                "encrypted": False,
                "apps": [],
            },
            {
                "device_id": "DEV-004",
                "name": "iPad Air",
                "platform": "iPadOS",
                "os_version": "17.4",
                "owner": "diana@corp.com",
                "enrolled": True,
                "encrypted": True,
                "apps": ["Authenticator", "Signal"],
            },
        ]

    async def check_enrollment(
        self, devices: list[dict[str, Any]]
    ) -> tuple[int, list[dict[str, Any]]]:
        """Check enrollment status of devices."""
        logger.info("mdm.enrollment", device_count=len(devices))
        unenrolled: list[dict[str, Any]] = []
        for d in devices:
            if not d.get("enrolled", False):
                unenrolled.append(
                    {
                        "device_id": d["device_id"],
                        "name": d.get("name", ""),
                        "owner": d.get("owner", ""),
                        "action": DeviceAction.ENROLL.value,
                    }
                )
        return len(unenrolled), unenrolled

    async def assess_compliance(
        self, devices: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], int, int]:
        """Assess compliance of each device."""
        logger.info("mdm.compliance", device_count=len(devices))
        violations: list[dict[str, Any]] = []
        compliant = 0
        non_compliant = 0

        for d in devices:
            dev_violations: list[str] = []
            if not d.get("enrolled", False):
                dev_violations.append("not_enrolled")
            if not d.get("encrypted", False):
                dev_violations.append("not_encrypted")

            if dev_violations:
                non_compliant += 1
                for v in dev_violations:
                    violations.append(
                        {
                            "device_id": d["device_id"],
                            "rule": v,
                            "expected": "true",
                            "actual": "false",
                            "severity": "high" if v == "not_encrypted" else "medium",
                        }
                    )
            else:
                compliant += 1

        return violations, compliant, non_compliant

    async def check_apps(self, devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Check for blocked apps on devices."""
        logger.info("mdm.check_apps")
        blocked: list[dict[str, Any]] = []
        for d in devices:
            for app in d.get("apps", []):
                if app in _BLOCKED_APPS:
                    blocked.append(
                        {
                            "device_id": d["device_id"],
                            "app_name": app,
                            "action": "remove",
                            "owner": d.get("owner", ""),
                        }
                    )
        return blocked

    async def enforce_policies(
        self,
        violations: list[dict[str, Any]],
        blocked_apps: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], int]:
        """Enforce MDM policies on non-compliant devices."""
        logger.info("mdm.enforce")
        actions: list[dict[str, Any]] = []
        encryption_enforced = 0

        for v in violations:
            if v.get("rule") == "not_encrypted":
                actions.append(
                    {
                        "id": _generate_id("ACT", v["device_id"]),
                        "device_id": v["device_id"],
                        "action": DeviceAction.RESTRICT.value,
                        "reason": "Encryption not enabled",
                    }
                )
                encryption_enforced += 1
            elif v.get("rule") == "not_enrolled":
                actions.append(
                    {
                        "id": _generate_id("ACT", v["device_id"]),
                        "device_id": v["device_id"],
                        "action": DeviceAction.NOTIFY.value,
                        "reason": "Device not enrolled in MDM",
                    }
                )

        for app in blocked_apps:
            actions.append(
                {
                    "id": _generate_id("ACT", app["device_id"], app["app_name"]),
                    "device_id": app["device_id"],
                    "action": DeviceAction.RESTRICT.value,
                    "reason": f"Blocked app: {app['app_name']}",
                }
            )

        return actions, encryption_enforced
