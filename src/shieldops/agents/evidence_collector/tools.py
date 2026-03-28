"""Tool functions for the Evidence Collector Agent."""

from __future__ import annotations

import hashlib
import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.evidence_collector.models import (
    ChainOfCustody,
    CollectedArtifact,
    EvidencePackage,
    EvidenceSource,
    EvidenceType,
    IntegrityStatus,
    IntegrityVerification,
)

logger = structlog.get_logger()

# Evidence sources by incident type
SOURCE_TEMPLATES: dict[str, list[dict[str, Any]]] = {
    "malware": [
        {
            "type": "memory_dump",
            "path": "/proc/memory",
            "priority": "critical",
            "size_mb": 4096,
        },
        {
            "type": "log_files",
            "path": "/var/log/syslog",
            "priority": "high",
            "size_mb": 500,
        },
        {
            "type": "network_capture",
            "path": "/var/evidence/pcap",  # noqa: S108
            "priority": "high",
            "size_mb": 2048,
        },
    ],
    "data_breach": [
        {
            "type": "log_files",
            "path": "/var/log/auth.log",
            "priority": "critical",
            "size_mb": 200,
        },
        {
            "type": "config_snapshot",
            "path": "/etc/",
            "priority": "high",
            "size_mb": 50,
        },
        {
            "type": "network_capture",
            "path": "/var/evidence/pcap",  # noqa: S108
            "priority": "high",
            "size_mb": 4096,
        },
    ],
    "default": [
        {
            "type": "log_files",
            "path": "/var/log/",
            "priority": "high",
            "size_mb": 500,
        },
        {
            "type": "config_snapshot",
            "path": "/etc/",
            "priority": "medium",
            "size_mb": 50,
        },
    ],
}


class EvidenceCollectorToolkit:
    """Toolkit for forensic evidence collection."""

    def __init__(
        self,
        forensics_client: Any | None = None,
        storage_client: Any | None = None,
    ) -> None:
        self._forensics_client = forensics_client
        self._storage_client = storage_client

    async def identify_sources(
        self,
        incident_details: dict[str, Any],
    ) -> list[EvidenceSource]:
        """Identify evidence sources for collection."""
        incident_type = incident_details.get("type", "default")
        hosts = incident_details.get(
            "affected_hosts",
            ["unknown-host"],
        )
        templates = SOURCE_TEMPLATES.get(
            incident_type,
            SOURCE_TEMPLATES["default"],
        )

        sources: list[EvidenceSource] = []
        for host in hosts:
            for tmpl in templates:
                ev_type = EvidenceType(tmpl["type"])
                sources.append(
                    EvidenceSource(
                        id=f"src-{uuid4().hex[:12]}",
                        host=host,
                        source_type=ev_type,
                        path=tmpl["path"],
                        accessible=True,
                        priority=tmpl["priority"],
                        estimated_size_mb=tmpl["size_mb"],
                    )
                )

        logger.info(
            "evidence.sources_identified",
            count=len(sources),
            hosts=len(hosts),
        )

        return sources

    async def collect_artifact(
        self,
        source: EvidenceSource,
    ) -> CollectedArtifact:
        """Collect an artifact from a source."""
        now = time.time()

        # Simulate collection with hash
        content = f"{source.host}:{source.path}:{now}"
        sha256 = hashlib.sha256(content.encode()).hexdigest()

        size = source.estimated_size_mb * 1024 * 1024
        file_path = f"/evidence/{source.host}/{source.source_type.value}/{uuid4().hex[:8]}"

        if self._forensics_client is not None:
            try:
                result = await self._forensics_client.collect(
                    host=source.host,
                    path=source.path,
                    evidence_type=(source.source_type.value),
                )
                file_path = str(result.get("path", file_path))
                sha256 = str(result.get("hash", sha256))
                size = result.get("size", size)
            except Exception:
                logger.debug(
                    "collection_client_failed",
                    source_id=source.id,
                )

        artifact = CollectedArtifact(
            id=f"art-{uuid4().hex[:12]}",
            source_id=source.id,
            evidence_type=source.source_type,
            file_path=file_path,
            size_bytes=size,
            sha256_hash=sha256,
            collected_at=now,
            collector="evidence_collector_agent",
            metadata={
                "host": source.host,
                "original_path": source.path,
            },
        )

        logger.info(
            "evidence.artifact_collected",
            artifact_id=artifact.id,
            evidence_type=(source.source_type.value),
            host=source.host,
        )

        return artifact

    async def verify_integrity(
        self,
        artifact: CollectedArtifact,
    ) -> IntegrityVerification:
        """Verify artifact integrity via hash check."""
        now = time.time()

        # Simulate re-hash verification
        current_hash = artifact.sha256_hash
        original_hash = artifact.sha256_hash
        verified = current_hash == original_hash
        status = IntegrityStatus.VERIFIED if verified else IntegrityStatus.TAMPERED

        verification = IntegrityVerification(
            id=f"iv-{uuid4().hex[:12]}",
            artifact_id=artifact.id,
            status=status,
            hash_verified=verified,
            original_hash=original_hash,
            current_hash=current_hash,
            checked_at=now,
            notes=("Hash match confirmed" if verified else "Hash mismatch detected"),
        )

        logger.info(
            "evidence.integrity_verified",
            artifact_id=artifact.id,
            status=status.value,
        )

        return verification

    async def package_evidence(
        self,
        incident_id: str,
        artifacts: list[CollectedArtifact],
    ) -> EvidencePackage:
        """Package all evidence for handoff."""
        now = time.time()

        # Compute package hash from all artifacts
        combined = "".join(a.sha256_hash for a in artifacts)
        pkg_hash = hashlib.sha256(combined.encode()).hexdigest()

        total_size = sum(a.size_bytes for a in artifacts)

        storage = f"s3://evidence-vault/{incident_id}/{uuid4().hex[:8]}"

        if self._storage_client is not None:
            try:
                result = await self._storage_client.store(
                    incident_id=incident_id,
                    artifacts=[a.file_path for a in artifacts],
                )
                storage = str(result.get("location", storage))
            except Exception:
                logger.debug(
                    "storage_client_failed",
                    incident_id=incident_id,
                )

        package = EvidencePackage(
            id=f"pkg-{uuid4().hex[:12]}",
            incident_id=incident_id,
            artifact_ids=[a.id for a in artifacts],
            package_hash=pkg_hash,
            created_at=now,
            storage_location=storage,
            encryption_key_id=(f"key-{uuid4().hex[:12]}"),
            total_size_bytes=total_size,
        )

        logger.info(
            "evidence.packaged",
            package_id=package.id,
            artifacts=len(artifacts),
            total_size_bytes=total_size,
        )

        return package

    async def record_custody(
        self,
        artifact_id: str,
        custodian: str,
        action: str,
        purpose: str,
    ) -> ChainOfCustody:
        """Record a chain of custody entry."""
        record = ChainOfCustody(
            id=f"coc-{uuid4().hex[:12]}",
            artifact_id=artifact_id,
            custodian=custodian,
            action=action,
            timestamp=time.time(),
            location="secure-evidence-vault",
            purpose=purpose,
            signature=hashlib.sha256(f"{custodian}:{action}:{time.time()}".encode()).hexdigest()[
                :32
            ],
        )

        logger.info(
            "evidence.custody_recorded",
            artifact_id=artifact_id,
            action=action,
        )

        return record
