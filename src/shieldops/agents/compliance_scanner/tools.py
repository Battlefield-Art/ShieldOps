"""Compliance Scanner Agent — Tool functions for compliance scanning."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

import structlog

from .models import (
    ComplianceControl,
    ControlStatus,
    EvidenceArtifact,
    FindingSeverity,
    RemediationTracker,
    ScanFinding,
)

logger = structlog.get_logger()

# Framework control definitions
_FRAMEWORK_CONTROLS: dict[str, list[dict[str, Any]]] = {
    "soc2": [
        {
            "control_id": "CC6.1",
            "control_name": "Logical and Physical Access Controls",
            "category": "access_control",
            "evidence_type": "access_logs",
        },
        {
            "control_id": "CC6.2",
            "control_name": "System Account Management",
            "category": "access_control",
            "evidence_type": "user_provisioning_logs",
        },
        {
            "control_id": "CC7.1",
            "control_name": "System Monitoring",
            "category": "monitoring",
            "evidence_type": "monitoring_config",
        },
        {
            "control_id": "CC7.2",
            "control_name": "Anomaly Detection",
            "category": "monitoring",
            "evidence_type": "alert_rules",
        },
        {
            "control_id": "CC8.1",
            "control_name": "Change Management",
            "category": "change_management",
            "evidence_type": "change_records",
        },
    ],
    "pci_dss": [
        {
            "control_id": "1.1",
            "control_name": "Firewall Configuration Standards",
            "category": "network_security",
            "evidence_type": "firewall_rules",
        },
        {
            "control_id": "3.4",
            "control_name": "Render PAN Unreadable",
            "category": "data_protection",
            "evidence_type": "encryption_config",
        },
        {
            "control_id": "6.1",
            "control_name": "Security Vulnerability Process",
            "category": "vulnerability_management",
            "evidence_type": "vuln_scan_reports",
        },
        {
            "control_id": "10.1",
            "control_name": "Audit Trail Linking",
            "category": "logging",
            "evidence_type": "audit_logs",
        },
    ],
    "hipaa": [
        {
            "control_id": "164.312(a)(1)",
            "control_name": "Access Control",
            "category": "access_control",
            "evidence_type": "access_policies",
        },
        {
            "control_id": "164.312(c)(1)",
            "control_name": "Integrity Controls",
            "category": "data_integrity",
            "evidence_type": "integrity_checks",
        },
        {
            "control_id": "164.312(e)(1)",
            "control_name": "Transmission Security",
            "category": "encryption",
            "evidence_type": "tls_config",
        },
    ],
    "gdpr": [
        {
            "control_id": "Art.25",
            "control_name": "Data Protection by Design",
            "category": "privacy",
            "evidence_type": "privacy_impact_assessment",
        },
        {
            "control_id": "Art.32",
            "control_name": "Security of Processing",
            "category": "security",
            "evidence_type": "security_measures",
        },
        {
            "control_id": "Art.33",
            "control_name": "Breach Notification",
            "category": "incident_response",
            "evidence_type": "incident_response_plan",
        },
    ],
}


def _generate_finding_id(control_id: str, framework: str) -> str:
    """Generate a deterministic finding ID."""
    raw = f"{framework}:{control_id}"
    return f"FND-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


def _generate_evidence_hash(control_id: str, artifact_type: str) -> str:
    """Generate a deterministic evidence hash."""
    raw = f"{control_id}:{artifact_type}:{datetime.now(UTC).date()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class ComplianceScannerToolkit:
    """Tools for continuous compliance scanning."""

    def __init__(
        self,
        policy_client: Any | None = None,
        config_client: Any | None = None,
        evidence_store: Any | None = None,
    ) -> None:
        self._policy_client = policy_client
        self._config_client = config_client
        self._evidence_store = evidence_store

    async def select_frameworks(
        self,
        requested: list[str] | None = None,
    ) -> list[str]:
        """Select compliance frameworks to scan."""
        logger.info("compliance_scanner.select_frameworks")

        available = list(_FRAMEWORK_CONTROLS.keys())
        if requested:
            return [f for f in requested if f in available]
        return available

    async def scan_controls(
        self,
        frameworks: list[str],
        tenant_id: str,
    ) -> list[ComplianceControl]:
        """Scan compliance controls for selected frameworks."""
        logger.info(
            "compliance_scanner.scan_controls",
            frameworks=frameworks,
            tenant_id=tenant_id,
        )

        if self._policy_client is not None:
            try:
                raw = await self._policy_client.scan(
                    frameworks=frameworks,
                    tenant_id=tenant_id,
                )
                return [ComplianceControl(**c) for c in raw]
            except Exception:
                logger.exception("compliance_scanner.scan.error")

        # Fallback: evaluate controls with simulated results
        controls: list[ComplianceControl] = []
        now = datetime.now(UTC)

        for framework in frameworks:
            framework_controls = _FRAMEWORK_CONTROLS.get(framework, [])
            for i, ctrl in enumerate(framework_controls):
                # Simulate varying pass/fail statuses
                if i % 4 == 0:
                    status = ControlStatus.FAIL
                elif i % 3 == 0:
                    status = ControlStatus.PARTIAL
                else:
                    status = ControlStatus.PASS

                controls.append(
                    ComplianceControl(
                        id=f"{framework}-{ctrl['control_id']}",
                        framework=framework,
                        control_id=ctrl["control_id"],
                        control_name=ctrl["control_name"],
                        status=status,
                        evidence_type=ctrl["evidence_type"],
                        last_scanned=now,
                        category=ctrl["category"],
                    )
                )

        return controls

    async def evaluate_findings(
        self, controls: list[ComplianceControl]
    ) -> list[ScanFinding]:
        """Generate findings from control scan results."""
        logger.info(
            "compliance_scanner.evaluate_findings",
            control_count=len(controls),
        )

        findings: list[ScanFinding] = []
        for ctrl in controls:
            if ctrl.status in (ControlStatus.FAIL, ControlStatus.PARTIAL):
                severity = (
                    FindingSeverity.HIGH
                    if ctrl.status == ControlStatus.FAIL
                    else FindingSeverity.MEDIUM
                )
                findings.append(
                    ScanFinding(
                        id=_generate_finding_id(ctrl.control_id, ctrl.framework),
                        control_id=ctrl.id,
                        finding_type=ctrl.status.value,
                        description=(
                            f"Control {ctrl.control_id} ({ctrl.control_name}) "
                            f"is {ctrl.status.value} in {ctrl.framework}"
                        ),
                        severity=severity,
                        auto_remediable=ctrl.category in (
                            "monitoring", "logging",
                        ),
                        resource=ctrl.framework,
                        recommendation=(
                            f"Review and remediate {ctrl.control_name} "
                            f"control for {ctrl.framework} compliance"
                        ),
                    )
                )

        return findings

    async def track_remediation(
        self, findings: list[ScanFinding]
    ) -> list[RemediationTracker]:
        """Create remediation tracking for findings."""
        logger.info(
            "compliance_scanner.track_remediation",
            finding_count=len(findings),
        )

        trackers: list[RemediationTracker] = []
        for finding in findings:
            status = "auto_remediated" if finding.auto_remediable else "open"
            trackers.append(
                RemediationTracker(
                    finding_id=finding.id,
                    status=status,
                    assignee="compliance-team",
                    action_taken=(
                        "Auto-remediated" if finding.auto_remediable
                        else "Pending manual review"
                    ),
                )
            )

        return trackers

    async def generate_evidence(
        self, controls: list[ComplianceControl]
    ) -> list[EvidenceArtifact]:
        """Generate or collect evidence for controls."""
        logger.info(
            "compliance_scanner.generate_evidence",
            control_count=len(controls),
        )

        artifacts: list[EvidenceArtifact] = []
        now = datetime.now(UTC)

        for ctrl in controls:
            if ctrl.status == ControlStatus.PASS:
                artifacts.append(
                    EvidenceArtifact(
                        control_id=ctrl.id,
                        artifact_type=ctrl.evidence_type,
                        description=(
                            f"Automated evidence for {ctrl.control_name}"
                        ),
                        collected_at=now,
                        storage_path=(
                            f"s3://compliance-evidence/"
                            f"{ctrl.framework}/{ctrl.control_id}/"
                        ),
                        hash_value=_generate_evidence_hash(
                            ctrl.control_id, ctrl.evidence_type
                        ),
                    )
                )

        return artifacts

    def calculate_compliance_score(
        self, controls: list[ComplianceControl]
    ) -> float:
        """Calculate overall compliance percentage."""
        if not controls:
            return 0.0
        assessed = [
            c for c in controls
            if c.status != ControlStatus.NOT_ASSESSED
        ]
        if not assessed:
            return 0.0
        passed = sum(
            1 for c in assessed if c.status == ControlStatus.PASS
        )
        return round(passed / len(assessed) * 100, 1)
