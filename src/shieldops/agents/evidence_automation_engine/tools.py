"""Evidence Automation Engine Agent — Tool functions."""

from __future__ import annotations

import hashlib
import time
from typing import Any

import structlog

from .models import EvidenceType, ValidationStatus

logger = structlog.get_logger()

_REQUIREMENTS: dict[str, list[dict[str, Any]]] = {
    "soc2": [
        {
            "control_id": "SOC2-CC6.1",
            "description": "Access control evidence",
            "evidence_type": "config_snapshot",
        },
        {
            "control_id": "SOC2-CC7.1",
            "description": "Monitoring evidence",
            "evidence_type": "log_export",
        },
        {
            "control_id": "SOC2-CC8.1",
            "description": "Change management evidence",
            "evidence_type": "screenshot",
        },
    ],
    "hipaa": [
        {
            "control_id": "HIPAA-164.312a",
            "description": "Access control logs",
            "evidence_type": "log_export",
        },
        {
            "control_id": "HIPAA-164.312e",
            "description": "Encryption configuration",
            "evidence_type": "config_snapshot",
        },
    ],
    "pci_dss": [
        {
            "control_id": "PCI-3.1",
            "description": "Data protection scan",
            "evidence_type": "scan_report",
        },
        {
            "control_id": "PCI-8.1",
            "description": "Authentication config",
            "evidence_type": "config_snapshot",
        },
    ],
}


class EvidenceAutomationEngineToolkit:
    """Tools for automated evidence collection."""

    def __init__(
        self,
        evidence_store: Any | None = None,
        scanner: Any | None = None,
        attestation_api: Any | None = None,
    ) -> None:
        self._evidence_store = evidence_store
        self._scanner = scanner
        self._attestation_api = attestation_api

    async def identify_requirements(
        self,
        frameworks: list[str],
    ) -> list[dict[str, Any]]:
        """Identify evidence requirements."""
        logger.info(
            "eae.identify_requirements",
            frameworks=frameworks,
        )

        if self._evidence_store is not None:
            try:
                return await self._evidence_store.get_requirements(
                    frameworks=frameworks,
                )
            except Exception:
                logger.exception("eae.identify.error")

        results: list[dict[str, Any]] = []
        idx = 0
        for fw in frameworks:
            reqs = _REQUIREMENTS.get(fw, [])
            for req in reqs:
                results.append(
                    {
                        "id": f"req-{fw}-{idx:03d}",
                        "control_id": req["control_id"],
                        "framework": fw,
                        "description": req["description"],
                        "evidence_type": req["evidence_type"],
                        "mandatory": True,
                    }
                )
                idx += 1
        return results

    async def collect_evidence(
        self,
        requirement: dict[str, Any],
    ) -> dict[str, Any]:
        """Collect evidence for a requirement."""
        logger.info(
            "eae.collect",
            req_id=requirement.get("id", ""),
        )

        if self._scanner is not None:
            try:
                return await self._scanner.collect(
                    requirement=requirement,
                )
            except Exception:
                logger.exception("eae.collect.error")

        now = time.time()
        content = f"evidence-{requirement.get('id', '')}"
        h = hashlib.sha256(
            content.encode(),
        ).hexdigest()[:16]

        return {
            "id": f"art-{h}",
            "requirement_id": requirement.get("id", ""),
            "evidence_type": requirement.get(
                "evidence_type",
                EvidenceType.LOG_EXPORT.value,
            ),
            "source": "automated_collection",
            "content_hash": h,
            "collected_at": now,
            "valid_until": now + 86400 * 90,
            "status": ValidationStatus.PENDING.value,
        }

    def validate_artifact(
        self,
        artifact: dict[str, Any],
    ) -> dict[str, Any]:
        """Validate an evidence artifact."""
        now = time.time()
        valid_until = artifact.get("valid_until", 0.0)
        has_hash = bool(artifact.get("content_hash"))

        if valid_until < now:
            status = ValidationStatus.EXPIRED.value
        elif not has_hash:
            status = ValidationStatus.INCOMPLETE.value
        else:
            status = ValidationStatus.VERIFIED.value

        artifact["status"] = status
        return artifact

    async def submit_attestation(
        self,
        framework: str,
        artifacts: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Submit attestation for a framework."""
        logger.info(
            "eae.submit_attestation",
            framework=framework,
        )

        if self._attestation_api is not None:
            try:
                return await self._attestation_api.submit(
                    framework=framework,
                    artifacts=artifacts,
                )
            except Exception:
                logger.exception("eae.submit.error")

        verified = sum(1 for a in artifacts if a.get("status") == "verified")
        return {
            "id": f"att-{framework}-{int(time.time())}",
            "framework": framework,
            "artifacts_count": len(artifacts),
            "submitted_at": time.time(),
            "accepted": verified == len(artifacts),
        }

    def generate_report(
        self,
        requirements: list[dict[str, Any]],
        artifacts: list[dict[str, Any]],
        attestations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Generate evidence collection report."""
        verified = sum(1 for a in artifacts if a.get("status") == "verified")
        rejected = sum(
            1
            for a in artifacts
            if a.get("status")
            in (
                "rejected",
                "expired",
                "incomplete",
            )
        )
        accepted = sum(1 for att in attestations if att.get("accepted"))

        return {
            "total_requirements": len(requirements),
            "artifacts_collected": len(artifacts),
            "artifacts_verified": verified,
            "artifacts_rejected": rejected,
            "attestations_submitted": len(attestations),
            "attestations_accepted": accepted,
            "coverage_pct": round(
                len(artifacts)
                / max(
                    len(requirements),
                    1,
                )
                * 100,
                1,
            ),
            "generated_at": time.time(),
        }
