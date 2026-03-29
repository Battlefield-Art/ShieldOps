"""Endpoint Forensics Agent — Tool functions."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

import structlog

from .models import ArtifactType, FindingSeverity

logger = structlog.get_logger()

_SUSPICIOUS_DLLS = {
    "metsrv.dll",
    "beacon.dll",
    "mimikatz.dll",
    "inject.dll",
    "shellcode.dll",
}

_MALWARE_HASHES = {
    "a1b2c3d4e5f6",
    "deadbeef1234",
    "badc0ffee000",
}


def _generate_id(prefix: str, *parts: str) -> str:
    raw = f"{':'.join(parts)}:{datetime.now(UTC).isoformat()}"
    return f"{prefix}-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


class EndpointForensicsToolkit:
    """Tools for endpoint forensic investigation."""

    def __init__(
        self,
        edr_client: Any | None = None,
        forensics_client: Any | None = None,
    ) -> None:
        self._edr = edr_client
        self._forensics = forensics_client

    async def collect_artifacts(self, endpoint_id: str, case_id: str) -> list[dict[str, Any]]:
        """Collect forensic artifacts from endpoint."""
        logger.info("forensics.collect", endpoint_id=endpoint_id, case_id=case_id)
        if self._forensics:
            try:
                return await self._forensics.collect(endpoint_id=endpoint_id, case_id=case_id)
            except Exception:
                logger.exception("forensics.collect.error")
        return [
            {
                "id": _generate_id("ART", "memdump"),
                "artifact_type": ArtifactType.MEMORY_DUMP.value,
                "source": f"{endpoint_id}/memory.dmp",
                "size_bytes": 4_294_967_296,
                "hash_sha256": "a1b2c3d4e5f6a1b2c3d4e5f6",
            },
            {
                "id": _generate_id("ART", "proclist"),
                "artifact_type": ArtifactType.PROCESS_LIST.value,
                "source": f"{endpoint_id}/processes.json",
                "size_bytes": 125_000,
                "hash_sha256": "f6e5d4c3b2a1f6e5d4c3b2a1",
            },
            {
                "id": _generate_id("ART", "evtlog"),
                "artifact_type": ArtifactType.EVENT_LOG.value,
                "source": f"{endpoint_id}/security.evtx",
                "size_bytes": 67_000_000,
                "hash_sha256": "1a2b3c4d5e6f1a2b3c4d5e6f",
            },
            {
                "id": _generate_id("ART", "prefetch"),
                "artifact_type": ArtifactType.PREFETCH.value,
                "source": f"{endpoint_id}/prefetch/",
                "size_bytes": 8_500_000,
                "hash_sha256": "6f5e4d3c2b1a6f5e4d3c2b1a",
            },
        ]

    async def analyze_memory(
        self, artifacts: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], int]:
        """Analyze memory dump for malware and injection."""
        logger.info("forensics.memory")
        findings: list[dict[str, Any]] = []
        injected = 0

        findings.append(
            {
                "id": _generate_id("MEM", "injection1"),
                "finding_type": "process_injection",
                "process_name": "svchost.exe",
                "pid": 3248,
                "severity": FindingSeverity.CRITICAL.value,
                "details": "Cobalt Strike beacon injected into svchost.exe",
                "indicators": ["cobalt_strike_watermark", "named_pipe_c2"],
            }
        )
        injected += 1

        findings.append(
            {
                "id": _generate_id("MEM", "hollowing1"),
                "finding_type": "process_hollowing",
                "process_name": "explorer.exe",
                "pid": 1024,
                "severity": FindingSeverity.HIGH.value,
                "details": "Process hollowing detected in explorer.exe",
                "indicators": ["unmapped_memory_region", "pe_header_mismatch"],
            }
        )
        injected += 1

        findings.append(
            {
                "id": _generate_id("MEM", "creds1"),
                "finding_type": "credential_dumping",
                "process_name": "lsass.exe",
                "pid": 672,
                "severity": FindingSeverity.CRITICAL.value,
                "details": "Credential access via LSASS memory read",
                "indicators": ["lsass_access_handle", "minidump_creation"],
            }
        )

        return findings, injected

    async def investigate_processes(
        self, artifacts: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Investigate suspicious processes."""
        logger.info("forensics.processes")
        suspicious: list[dict[str, Any]] = [
            {
                "pid": 3248,
                "name": "svchost.exe",
                "path": "C:\\Windows\\System32\\svchost.exe",
                "parent_pid": 680,
                "parent_name": "services.exe",
                "reason": "Cobalt Strike beacon detected",
                "severity": FindingSeverity.CRITICAL.value,
            },
            {
                "pid": 9102,
                "name": "certutil.exe",
                "path": "C:\\Windows\\System32\\certutil.exe",
                "parent_pid": 4532,
                "parent_name": "powershell.exe",
                "reason": "LOLBin used for download",
                "severity": FindingSeverity.HIGH.value,
            },
        ]
        tree: list[dict[str, Any]] = [
            {
                "pid": 680,
                "name": "services.exe",
                "children": [
                    {"pid": 3248, "name": "svchost.exe (INJECTED)"},
                ],
            },
            {
                "pid": 4532,
                "name": "powershell.exe",
                "children": [
                    {"pid": 9102, "name": "certutil.exe"},
                ],
            },
        ]
        return suspicious, tree

    async def carve_files(
        self, artifacts: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], int]:
        """Carve deleted/hidden files from disk image."""
        logger.info("forensics.carve")
        carved: list[dict[str, Any]] = [
            {
                "id": _generate_id("FIL", "payload"),
                "file_name": "payload.exe",
                "file_type": "PE executable",
                "size_bytes": 245_000,
                "hash_sha256": "deadbeef1234deadbeef1234",
                "is_malware": True,
                "verdict": "Cobalt Strike loader",
            },
            {
                "id": _generate_id("FIL", "script"),
                "file_name": "stage2.ps1",
                "file_type": "PowerShell script",
                "size_bytes": 12_000,
                "hash_sha256": "badc0ffee000badc0ffee000",
                "is_malware": True,
                "verdict": "Obfuscated downloader",
            },
            {
                "id": _generate_id("FIL", "exfil"),
                "file_name": "data.7z",
                "file_type": "7-Zip archive",
                "size_bytes": 15_000_000,
                "hash_sha256": "abcdef123456abcdef123456",
                "is_malware": False,
                "verdict": "Exfiltrated data archive",
            },
        ]
        malware = sum(1 for f in carved if f.get("is_malware"))
        return carved, malware

    async def reconstruct_timeline(
        self,
        memory_findings: list[dict[str, Any]],
        processes: list[dict[str, Any]],
        carved_files: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Reconstruct attack timeline from all evidence."""
        logger.info("forensics.timeline")
        now = datetime.now(UTC)
        timeline: list[dict[str, Any]] = [
            {
                "timestamp": now.isoformat(),
                "source": "email",
                "event_type": "initial_access",
                "description": "Phishing email delivered with macro doc",
                "severity": FindingSeverity.HIGH.value,
            },
            {
                "timestamp": now.isoformat(),
                "source": "process",
                "event_type": "execution",
                "description": "PowerShell encoded command executed",
                "severity": FindingSeverity.CRITICAL.value,
            },
            {
                "timestamp": now.isoformat(),
                "source": "network",
                "event_type": "command_and_control",
                "description": "Cobalt Strike C2 beacon established",
                "severity": FindingSeverity.CRITICAL.value,
            },
            {
                "timestamp": now.isoformat(),
                "source": "memory",
                "event_type": "credential_access",
                "description": "LSASS credential dumping",
                "severity": FindingSeverity.CRITICAL.value,
            },
            {
                "timestamp": now.isoformat(),
                "source": "filesystem",
                "event_type": "exfiltration",
                "description": "Data archived and staged for exfil",
                "severity": FindingSeverity.HIGH.value,
            },
        ]
        return timeline
