"""USB Device Controller Agent — Tool functions."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

import structlog

from .models import DeviceClassification, TransferRisk

logger = structlog.get_logger()

_WHITELIST = {
    "USB\\VID_046D&PID_C52B": "Logitech Receiver",
    "USB\\VID_8087&PID_0026": "Intel Bluetooth",
    "USB\\VID_05AC&PID_8290": "Apple Keyboard",
    "USB\\VID_413C&PID_2107": "Dell Keyboard",
}

_SENSITIVE_EXTENSIONS = {
    ".docx",
    ".xlsx",
    ".pdf",
    ".csv",
    ".sql",
    ".db",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".env",
}


def _generate_id(prefix: str, *parts: str) -> str:
    raw = f"{':'.join(parts)}:{datetime.now(UTC).isoformat()}"
    return f"{prefix}-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


class USBDeviceControllerToolkit:
    """Tools for USB device control operations."""

    def __init__(
        self,
        endpoint_client: Any | None = None,
        dlp_client: Any | None = None,
    ) -> None:
        self._endpoint = endpoint_client
        self._dlp = dlp_client

    async def scan_devices(self, tenant_id: str) -> list[dict[str, Any]]:
        """Scan for connected USB devices across endpoints."""
        logger.info("usb.scan", tenant_id=tenant_id)
        if self._endpoint:
            try:
                return await self._endpoint.list_usb_devices(tenant_id=tenant_id)
            except Exception:
                logger.exception("usb.scan.error")
        return [
            {
                "device_id": "USB\\VID_046D&PID_C52B",
                "vendor_id": "046D",
                "product_id": "C52B",
                "serial": "ABC123",
                "device_name": "Logitech Receiver",
                "device_type": "hid",
                "endpoint_id": "EP-001",
                "user": "alice@corp.com",
            },
            {
                "device_id": "USB\\VID_0781&PID_5567",
                "vendor_id": "0781",
                "product_id": "5567",
                "serial": "XYZ789",
                "device_name": "SanDisk Cruzer",
                "device_type": "mass_storage",
                "endpoint_id": "EP-002",
                "user": "bob@corp.com",
            },
            {
                "device_id": "USB\\VID_DEAD&PID_BEEF",
                "vendor_id": "DEAD",
                "product_id": "BEEF",
                "serial": "UNK001",
                "device_name": "Unknown Device",
                "device_type": "mass_storage",
                "endpoint_id": "EP-003",
                "user": "charlie@corp.com",
            },
        ]

    async def check_whitelist(
        self, devices: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], int, int]:
        """Check devices against whitelist."""
        logger.info("usb.whitelist", device_count=len(devices))
        unauthorized: list[dict[str, Any]] = []
        whitelisted = 0

        for d in devices:
            dev_id = d.get("device_id", "")
            if dev_id in _WHITELIST:
                d["classification"] = DeviceClassification.WHITELISTED.value
                whitelisted += 1
            else:
                d["classification"] = DeviceClassification.UNAUTHORIZED.value
                unauthorized.append(d)

        return unauthorized, whitelisted, len(unauthorized)

    async def monitor_transfers(
        self, devices: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], int, int]:
        """Monitor data transfers from USB devices."""
        logger.info("usb.monitor_transfers")
        transfers: list[dict[str, Any]] = []
        blocked = 0
        suspicious = 0
        now = datetime.now(UTC)

        storage_devices = [d for d in devices if d.get("device_type") == "mass_storage"]

        for d in storage_devices:
            is_unauthorized = d.get("classification") == DeviceClassification.UNAUTHORIZED.value
            # Simulate detected transfers
            transfer = {
                "id": _generate_id("TXF", d["device_id"]),
                "device_id": d["device_id"],
                "endpoint_id": d.get("endpoint_id", ""),
                "direction": "outbound",
                "file_name": "report.xlsx",
                "file_size": 2_500_000,
                "file_type": ".xlsx",
                "risk": TransferRisk.HIGH.value,
                "blocked": is_unauthorized,
                "timestamp": now.isoformat(),
            }
            transfers.append(transfer)
            if is_unauthorized:
                blocked += 1
            if transfer["file_type"] in _SENSITIVE_EXTENSIONS:
                suspicious += 1

        return transfers, blocked, suspicious

    async def enforce_policy(
        self,
        unauthorized: list[dict[str, Any]],
        transfers: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], int]:
        """Enforce USB device control policies."""
        logger.info("usb.enforce")
        enforcements: list[dict[str, Any]] = []

        for d in unauthorized:
            enforcements.append(
                {
                    "id": _generate_id("ENF", d["device_id"]),
                    "device_id": d["device_id"],
                    "endpoint_id": d.get("endpoint_id", ""),
                    "action": "block",
                    "reason": "Unauthorized USB device",
                    "user": d.get("user", ""),
                }
            )

        for t in transfers:
            if t.get("blocked"):
                enforcements.append(
                    {
                        "id": _generate_id("ENF", t["device_id"], "transfer"),
                        "device_id": t["device_id"],
                        "endpoint_id": t.get("endpoint_id", ""),
                        "action": "block_transfer",
                        "reason": f"Blocked transfer: {t.get('file_name', '')}",
                    }
                )

        return enforcements, len(enforcements)
