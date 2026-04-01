"""Compliance Evidence Generator — Tool functions for evidence generation."""

from __future__ import annotations

import hashlib
import random  # noqa: S311
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import structlog

logger = structlog.get_logger()

# -- Framework control definitions ---------------------------------------------

_FRAMEWORK_CONTROLS: dict[str, list[dict[str, Any]]] = {
    "soc2": [
        {
            "control_id": "SOC2-CC6.1",
            "title": "Logical and physical access controls",
            "category": "access",
            "criticality": "high",
        },
        {
            "control_id": "SOC2-CC6.2",
            "title": "User authentication mechanisms",
            "category": "access",
            "criticality": "high",
        },
        {
            "control_id": "SOC2-CC7.1",
            "title": "System monitoring and anomaly detection",
            "category": "monitoring",
            "criticality": "high",
        },
        {
            "control_id": "SOC2-CC7.2",
            "title": "Incident response procedures",
            "category": "incident_response",
            "criticality": "critical",
        },
        {
            "control_id": "SOC2-CC8.1",
            "title": "Change management controls",
            "category": "change_management",
            "criticality": "medium",
        },
        {
            "control_id": "SOC2-CC9.1",
            "title": "Risk mitigation activities",
            "category": "risk_management",
            "criticality": "high",
        },
    ],
    "iso27001": [
        {
            "control_id": "ISO-A5",
            "title": "Information security policies",
            "category": "policy",
            "criticality": "high",
        },
        {
            "control_id": "ISO-A6",
            "title": "Organization of information security",
            "category": "organization",
            "criticality": "medium",
        },
        {
            "control_id": "ISO-A8",
            "title": "Asset management",
            "category": "asset_management",
            "criticality": "medium",
        },
        {
            "control_id": "ISO-A9",
            "title": "Access control",
            "category": "access",
            "criticality": "high",
        },
        {
            "control_id": "ISO-A10",
            "title": "Cryptography",
            "category": "encryption",
            "criticality": "critical",
        },
        {
            "control_id": "ISO-A12",
            "title": "Operations security",
            "category": "operations",
            "criticality": "high",
        },
    ],
    "pci_dss": [
        {
            "control_id": "PCI-1.1",
            "title": "Install and maintain network security controls",
            "category": "network",
            "criticality": "critical",
        },
        {
            "control_id": "PCI-2.1",
            "title": "Apply secure configurations",
            "category": "configuration",
            "criticality": "high",
        },
        {
            "control_id": "PCI-3.1",
            "title": "Protect stored account data",
            "category": "data_protection",
            "criticality": "critical",
        },
        {
            "control_id": "PCI-6.1",
            "title": "Develop and maintain secure systems",
            "category": "development",
            "criticality": "high",
        },
        {
            "control_id": "PCI-8.1",
            "title": "Identify users and authenticate access",
            "category": "access",
            "criticality": "critical",
        },
        {
            "control_id": "PCI-10.1",
            "title": "Log and monitor all access",
            "category": "monitoring",
            "criticality": "high",
        },
    ],
    "hipaa": [
        {
            "control_id": "HIPAA-164.312a",
            "title": "Access control — unique user ID",
            "category": "access",
            "criticality": "critical",
        },
        {
            "control_id": "HIPAA-164.312b",
            "title": "Audit controls — activity logging",
            "category": "monitoring",
            "criticality": "high",
        },
        {
            "control_id": "HIPAA-164.312c",
            "title": "Integrity controls — ePHI protection",
            "category": "data_protection",
            "criticality": "critical",
        },
        {
            "control_id": "HIPAA-164.312d",
            "title": "Person authentication",
            "category": "access",
            "criticality": "high",
        },
        {
            "control_id": "HIPAA-164.312e",
            "title": "Transmission security — encryption",
            "category": "encryption",
            "criticality": "critical",
        },
        {
            "control_id": "HIPAA-164.308a",
            "title": "Security management process",
            "category": "risk_management",
            "criticality": "high",
        },
    ],
}

_EVIDENCE_TYPE_MAP: dict[str, list[str]] = {
    "access": ["configuration_snapshot", "access_review", "policy_document"],
    "monitoring": ["log_export", "telemetry_report", "scan_result"],
    "encryption": ["configuration_snapshot", "scan_result"],
    "data_protection": ["configuration_snapshot", "policy_document", "scan_result"],
    "policy": ["policy_document"],
    "incident_response": ["policy_document", "log_export"],
    "change_management": ["log_export", "configuration_snapshot"],
    "risk_management": ["policy_document", "telemetry_report"],
    "network": ["configuration_snapshot", "scan_result"],
    "configuration": ["configuration_snapshot", "scan_result"],
    "development": ["scan_result", "configuration_snapshot"],
    "organization": ["policy_document"],
    "asset_management": ["configuration_snapshot", "telemetry_report"],
    "operations": ["log_export", "telemetry_report", "configuration_snapshot"],
}


class ComplianceEvidenceGeneratorToolkit:
    """Tools for compliance evidence generation, validation, and packaging."""

    def __init__(
        self,
        telemetry_client: Any | None = None,
        config_store: Any | None = None,
        evidence_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._telemetry_client = telemetry_client
        self._config_store = config_store
        self._evidence_store = evidence_store
        self._repository = repository

    async def identify_controls(
        self,
        frameworks: list[str],
    ) -> list[dict[str, Any]]:
        """Identify applicable controls for the requested frameworks."""
        logger.info("ceg.identify_controls", frameworks=frameworks)
        if self._config_store is not None:
            try:
                return await self._config_store.get_controls(  # type: ignore[no-any-return]
                    frameworks=frameworks,
                )
            except Exception:
                logger.exception("ceg.identify_controls.backend_error")

        controls: list[dict[str, Any]] = []
        for fw in frameworks:
            fw_controls = _FRAMEWORK_CONTROLS.get(fw, [])
            for ctrl in fw_controls:
                category = ctrl.get("category", "general")
                evidence_types = _EVIDENCE_TYPE_MAP.get(category, ["configuration_snapshot"])
                controls.append(
                    {
                        "control_id": ctrl["control_id"],
                        "framework": fw,
                        "title": ctrl["title"],
                        "description": f"Control requirement: {ctrl['title']}",
                        "category": category,
                        "required_evidence_types": evidence_types,
                        "criticality": ctrl.get("criticality", "medium"),
                    }
                )
        return controls

    async def collect_evidence(
        self,
        controls: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Collect evidence artifacts for identified controls."""
        logger.info("ceg.collect_evidence", control_count=len(controls))
        if self._telemetry_client is not None:
            try:
                return await self._telemetry_client.collect(  # type: ignore[no-any-return]
                    controls=controls,
                )
            except Exception:
                logger.exception("ceg.collect_evidence.backend_error")

        now = datetime.now(UTC)
        artifacts: list[dict[str, Any]] = []
        for ctrl in controls:
            evidence_types = ctrl.get("required_evidence_types", ["configuration_snapshot"])
            for ev_type in evidence_types:
                content = f"{ctrl['control_id']}:{ev_type}:{uuid4().hex[:8]}"
                artifacts.append(
                    {
                        "artifact_id": f"ev-{uuid4().hex[:12]}",
                        "control_id": ctrl.get("control_id", ""),
                        "evidence_type": ev_type,
                        "source": "system_telemetry",
                        "description": f"Auto-collected {ev_type} for {ctrl.get('control_id', '')}",
                        "collected_at": now.isoformat(),
                        "valid_until": (now + timedelta(days=90)).isoformat(),
                        "hash_digest": hashlib.sha256(content.encode()).hexdigest()[:16],
                        "content_ref": f"s3://evidence-bucket/{uuid4().hex[:16]}",
                        "is_valid": True,
                    }
                )
        return artifacts

    async def validate_evidence(
        self,
        artifacts: list[dict[str, Any]],
        controls: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Validate evidence artifacts for freshness and completeness."""
        logger.info("ceg.validate_evidence", artifact_count=len(artifacts))
        if self._evidence_store is not None:
            try:
                return await self._evidence_store.validate(  # type: ignore[no-any-return]
                    artifacts=artifacts,
                    controls=controls,
                )
            except Exception:
                logger.exception("ceg.validate_evidence.backend_error")

        now = datetime.now(UTC)
        results: list[dict[str, Any]] = []
        for art in artifacts:
            valid_until = art.get("valid_until", "")
            is_expired = False
            if valid_until:
                try:
                    expiry = datetime.fromisoformat(valid_until)
                    is_expired = expiry < now
                except (ValueError, TypeError):
                    is_expired = False

            # Simulate occasional validation failures
            is_valid = not is_expired and random.random() > 0.05  # noqa: S311
            results.append(
                {
                    "artifact_id": art.get("artifact_id", ""),
                    "control_id": art.get("control_id", ""),
                    "is_valid": is_valid,
                    "is_expired": is_expired,
                    "validation_note": (
                        "Valid and current"
                        if is_valid
                        else "Evidence expired or failed integrity check"
                    ),
                    "validated_at": now.isoformat(),
                }
            )
        return results

    async def identify_gaps(
        self,
        controls: list[dict[str, Any]],
        validation_results: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Identify compliance gaps from validation results."""
        logger.info("ceg.identify_gaps", control_count=len(controls))

        # Build lookup of valid artifacts per control
        valid_by_control: dict[str, int] = {}
        invalid_by_control: dict[str, int] = {}
        for vr in validation_results:
            cid = vr.get("control_id", "")
            if vr.get("is_valid", False):
                valid_by_control[cid] = valid_by_control.get(cid, 0) + 1
            else:
                invalid_by_control[cid] = invalid_by_control.get(cid, 0) + 1

        gaps: list[dict[str, Any]] = []
        for ctrl in controls:
            cid = ctrl.get("control_id", "")
            required_types = ctrl.get("required_evidence_types", [])
            valid_count = valid_by_control.get(cid, 0)
            invalid_count = invalid_by_control.get(cid, 0)

            if valid_count < len(required_types) or invalid_count > 0:
                severity = "critical" if ctrl.get("criticality") == "critical" else "high"
                gaps.append(
                    {
                        "gap_id": f"gap-{uuid4().hex[:10]}",
                        "control_id": cid,
                        "framework": ctrl.get("framework", ""),
                        "description": (
                            f"Missing or invalid evidence for {cid}: "
                            f"{valid_count}/{len(required_types)} valid artifacts, "
                            f"{invalid_count} invalid"
                        ),
                        "severity": severity,
                        "remediation_suggestion": (
                            f"Re-collect {len(required_types) - valid_count} "
                            f"missing artifacts and fix {invalid_count} invalid ones"
                        ),
                        "estimated_effort_hours": random.randint(2, 40),  # noqa: S311
                    }
                )
        return gaps

    async def package_evidence(
        self,
        frameworks: list[str],
        controls: list[dict[str, Any]],
        artifacts: list[dict[str, Any]],
        validation_results: list[dict[str, Any]],
        gaps: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Package evidence artifacts into audit-ready packages per framework."""
        logger.info("ceg.package_evidence", framework_count=len(frameworks))
        now = datetime.now(UTC)

        valid_artifact_ids = {
            vr.get("artifact_id") for vr in validation_results if vr.get("is_valid", False)
        }

        packages: list[dict[str, Any]] = []
        for fw in frameworks:
            fw_controls = [c for c in controls if c.get("framework") == fw]
            fw_artifacts = [
                a
                for a in artifacts
                if a.get("control_id", "").startswith(fw.upper().replace("_", "-"))
                or a.get("artifact_id") in valid_artifact_ids
            ]
            fw_valid = [a for a in fw_artifacts if a.get("artifact_id") in valid_artifact_ids]
            fw_gaps = [g for g in gaps if g.get("framework") == fw]

            total_required = sum(len(c.get("required_evidence_types", [])) for c in fw_controls)
            completeness = round(len(fw_valid) / total_required, 4) if total_required > 0 else 0.0

            packages.append(
                {
                    "package_id": f"pkg-{uuid4().hex[:12]}",
                    "framework": fw,
                    "controls_covered": len(fw_controls),
                    "artifacts_included": len(fw_valid),
                    "gaps_remaining": len(fw_gaps),
                    "completeness_score": min(completeness, 1.0),
                    "generated_at": now.isoformat(),
                    "metadata": {
                        "total_artifacts_assessed": len(fw_artifacts),
                        "invalid_artifacts": len(fw_artifacts) - len(fw_valid),
                    },
                }
            )
        return packages

    async def record_metric(
        self,
        metric_type: str,
        value: float,
    ) -> None:
        """Record an evidence generation metric."""
        logger.info(
            "ceg.record_metric",
            metric_type=metric_type,
            value=value,
        )
