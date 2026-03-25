"""Compliance Reporter Agent — Tool functions for evidence collection and report generation."""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any

import structlog

from .models import (
    ArtifactPackage,
    ComplianceReport,
    ControlAssessment,
    ControlStatus,
    DeliveryResult,
    EvidenceItem,
)

logger = structlog.get_logger()

# Predefined control sets per framework
FRAMEWORK_CONTROLS: dict[str, list[dict[str, str]]] = {
    "soc2_type2": [
        {"control_id": "SOC2-CC1.1", "name": "COSO principle 1 — integrity and ethical values"},
        {"control_id": "SOC2-CC2.1", "name": "Board oversight of internal control"},
        {"control_id": "SOC2-CC3.1", "name": "Risk assessment process"},
        {"control_id": "SOC2-CC4.1", "name": "Monitoring activities and evaluations"},
        {"control_id": "SOC2-CC5.1", "name": "Control activities over technology"},
        {"control_id": "SOC2-CC6.1", "name": "Logical and physical access controls"},
        {"control_id": "SOC2-CC6.2", "name": "User authentication mechanisms"},
        {"control_id": "SOC2-CC6.3", "name": "Authorization and access provisioning"},
        {"control_id": "SOC2-CC7.1", "name": "System monitoring and anomaly detection"},
        {"control_id": "SOC2-CC7.2", "name": "Incident response procedures"},
        {"control_id": "SOC2-CC8.1", "name": "Change management controls"},
        {"control_id": "SOC2-CC9.1", "name": "Risk mitigation activities"},
    ],
    "pci_dss_4": [
        {"control_id": "PCI-1.1", "name": "Install and maintain network security controls"},
        {"control_id": "PCI-2.1", "name": "Apply secure configurations to all components"},
        {"control_id": "PCI-3.1", "name": "Protect stored account data"},
        {"control_id": "PCI-4.1", "name": "Protect cardholder data with strong cryptography"},
        {"control_id": "PCI-5.1", "name": "Protect all systems from malware"},
        {"control_id": "PCI-6.1", "name": "Develop and maintain secure systems and software"},
        {"control_id": "PCI-7.1", "name": "Restrict access to system components"},
        {"control_id": "PCI-8.1", "name": "Identify users and authenticate access"},
        {"control_id": "PCI-9.1", "name": "Restrict physical access to cardholder data"},
        {"control_id": "PCI-10.1", "name": "Log and monitor all access to system components"},
        {"control_id": "PCI-11.1", "name": "Test security of systems and networks regularly"},
        {"control_id": "PCI-12.1", "name": "Support information security with policies"},
    ],
    "hipaa": [
        {"control_id": "HIPAA-164.308a1", "name": "Security management process"},
        {"control_id": "HIPAA-164.308a3", "name": "Workforce security"},
        {"control_id": "HIPAA-164.308a4", "name": "Information access management"},
        {"control_id": "HIPAA-164.308a5", "name": "Security awareness and training"},
        {"control_id": "HIPAA-164.308a6", "name": "Security incident procedures"},
        {"control_id": "HIPAA-164.308a7", "name": "Contingency plan"},
        {"control_id": "HIPAA-164.310a1", "name": "Facility access controls"},
        {"control_id": "HIPAA-164.310b", "name": "Workstation use"},
        {"control_id": "HIPAA-164.312a", "name": "Access control — unique user ID"},
        {"control_id": "HIPAA-164.312b", "name": "Audit controls — activity logging"},
        {"control_id": "HIPAA-164.312c", "name": "Integrity controls — ePHI protection"},
        {"control_id": "HIPAA-164.312e", "name": "Transmission security — encryption"},
    ],
    "fedramp_moderate": [
        {"control_id": "AC-2", "name": "Account management"},
        {"control_id": "AC-3", "name": "Access enforcement"},
        {"control_id": "AU-2", "name": "Audit events"},
        {"control_id": "AU-6", "name": "Audit review, analysis, and reporting"},
        {"control_id": "CA-7", "name": "Continuous monitoring"},
        {"control_id": "CM-6", "name": "Configuration settings"},
        {"control_id": "IA-2", "name": "Identification and authentication"},
        {"control_id": "IR-4", "name": "Incident handling"},
        {"control_id": "RA-5", "name": "Vulnerability monitoring and scanning"},
        {"control_id": "SC-7", "name": "Boundary protection"},
        {"control_id": "SC-8", "name": "Transmission confidentiality and integrity"},
        {"control_id": "SI-4", "name": "System monitoring"},
    ],
    "gdpr": [
        {"control_id": "GDPR-Art5", "name": "Principles of data processing"},
        {"control_id": "GDPR-Art6", "name": "Lawfulness of processing"},
        {"control_id": "GDPR-Art13", "name": "Information to be provided to data subject"},
        {"control_id": "GDPR-Art17", "name": "Right to erasure"},
        {"control_id": "GDPR-Art25", "name": "Data protection by design and default"},
        {"control_id": "GDPR-Art30", "name": "Records of processing activities"},
        {"control_id": "GDPR-Art32", "name": "Security of processing"},
        {"control_id": "GDPR-Art33", "name": "Breach notification to authority"},
        {"control_id": "GDPR-Art35", "name": "Data protection impact assessment"},
        {"control_id": "GDPR-Art37", "name": "Designation of data protection officer"},
    ],
    "iso_27001": [
        {"control_id": "ISO-A5", "name": "Information security policies"},
        {"control_id": "ISO-A6", "name": "Organization of information security"},
        {"control_id": "ISO-A7", "name": "Human resource security"},
        {"control_id": "ISO-A8", "name": "Asset management"},
        {"control_id": "ISO-A9", "name": "Access control"},
        {"control_id": "ISO-A10", "name": "Cryptography"},
        {"control_id": "ISO-A11", "name": "Physical and environmental security"},
        {"control_id": "ISO-A12", "name": "Operations security"},
        {"control_id": "ISO-A13", "name": "Communications security"},
        {"control_id": "ISO-A14", "name": "System acquisition, development, maintenance"},
    ],
    "nist_csf": [
        {"control_id": "NIST-ID.AM", "name": "Asset management"},
        {"control_id": "NIST-ID.RA", "name": "Risk assessment"},
        {"control_id": "NIST-PR.AC", "name": "Identity management and access control"},
        {"control_id": "NIST-PR.DS", "name": "Data security"},
        {"control_id": "NIST-PR.IP", "name": "Information protection processes"},
        {"control_id": "NIST-DE.AE", "name": "Anomalies and events"},
        {"control_id": "NIST-DE.CM", "name": "Security continuous monitoring"},
        {"control_id": "NIST-RS.RP", "name": "Response planning"},
        {"control_id": "NIST-RS.MI", "name": "Mitigation"},
        {"control_id": "NIST-RC.RP", "name": "Recovery planning"},
    ],
}

# Evidence types for different kinds of artifacts
_EVIDENCE_TYPES = [
    "configuration_snapshot",
    "audit_log",
    "policy_document",
    "access_review",
    "penetration_test",
    "vulnerability_scan",
    "training_record",
    "incident_report",
]


class ComplianceReporterToolkit:
    """Tools for evidence collection, control assessment, and report generation."""

    def __init__(
        self,
        evidence_store: Any | None = None,
        policy_engine: Any | None = None,
        delivery_service: Any | None = None,
    ) -> None:
        self._evidence_store = evidence_store
        self._policy_engine = policy_engine
        self._delivery_service = delivery_service

    async def collect_evidence(
        self,
        framework: str,
        controls: list[dict[str, str]],
    ) -> list[EvidenceItem]:
        """Gather evidence from logs, configs, policies, and audit trails."""
        logger.info(
            "compliance_reporter.collect_evidence",
            framework=framework,
            control_count=len(controls),
        )
        if self._evidence_store is not None:
            try:
                raw = await self._evidence_store.collect(framework=framework, controls=controls)
                return [EvidenceItem(**e) for e in raw]
            except Exception:
                logger.exception("compliance_reporter.collect_evidence.error")
                return []

        # Mock: generate realistic evidence items per control
        now = time.time()
        items: list[EvidenceItem] = []
        for i, ctrl in enumerate(controls):
            control_id = ctrl.get("control_id", f"CTRL-{i}")
            ev_type = _EVIDENCE_TYPES[i % len(_EVIDENCE_TYPES)]
            content = f"{framework}:{control_id}:{ev_type}:{now}"
            digest = hashlib.sha256(content.encode()).hexdigest()
            items.append(
                EvidenceItem(
                    id=f"ev-{control_id}-{uuid.uuid4().hex[:8]}",
                    control_id=control_id,
                    framework=framework,
                    title=f"Evidence for {control_id}",
                    description=f"Automated {ev_type} for {ctrl.get('name', control_id)}",
                    evidence_type=ev_type,
                    source="shieldops_automated_collection",
                    collected_at=now,
                    artifact_path=f"/evidence/{framework}/{control_id}/{ev_type}.json",
                    hash_digest=digest,
                    verified=True,
                )
            )
        return items

    async def assess_controls(
        self,
        framework: str,
        evidence: list[EvidenceItem],
    ) -> list[ControlAssessment]:
        """Evaluate each control against collected evidence."""
        logger.info(
            "compliance_reporter.assess_controls",
            framework=framework,
            evidence_count=len(evidence),
        )
        if self._policy_engine is not None:
            try:
                raw = await self._policy_engine.assess(framework=framework, evidence=evidence)
                return [ControlAssessment(**a) for a in raw]
            except Exception:
                logger.exception("compliance_reporter.assess_controls.error")
                return []

        # Build evidence lookup by control_id
        evidence_by_ctrl: dict[str, list[EvidenceItem]] = {}
        for ev in evidence:
            evidence_by_ctrl.setdefault(ev.control_id, []).append(ev)

        controls = FRAMEWORK_CONTROLS.get(framework, [])
        now = time.time()
        assessments: list[ControlAssessment] = []
        for i, ctrl in enumerate(controls):
            control_id = ctrl.get("control_id", f"CTRL-{i}")
            ctrl_evidence = evidence_by_ctrl.get(control_id, [])
            ev_ids = [e.id for e in ctrl_evidence]

            # Heuristic status assignment for mock
            if not ctrl_evidence:
                status = ControlStatus.PENDING_EVIDENCE
                findings = [f"No evidence collected for {control_id}"]
                remediation = ["Collect required evidence artifacts"]
            elif i % 5 == 1:
                status = ControlStatus.PARTIALLY_COMPLIANT
                findings = ["Partial implementation detected"]
                remediation = ["Complete remaining configuration items"]
            elif i % 7 == 0 and i > 0:
                status = ControlStatus.NON_COMPLIANT
                findings = ["Control requirements not fully met"]
                remediation = [
                    "Review control requirements",
                    "Implement missing safeguards",
                    "Re-assess after remediation",
                ]
            else:
                status = ControlStatus.COMPLIANT
                findings = []
                remediation = []

            assessments.append(
                ControlAssessment(
                    id=f"ca-{control_id}-{uuid.uuid4().hex[:8]}",
                    control_id=control_id,
                    framework=framework,
                    control_name=ctrl.get("name", ""),
                    status=status,
                    findings=findings,
                    evidence_ids=ev_ids,
                    remediation_steps=remediation,
                    assessor_notes="Automated assessment by ShieldOps Compliance Reporter",
                    last_assessed=now,
                )
            )
        return assessments

    async def generate_report(
        self,
        framework: str,
        assessments: list[ControlAssessment],
        period_start: str,
        period_end: str,
    ) -> ComplianceReport:
        """Compile assessments into a formal compliance report."""
        logger.info(
            "compliance_reporter.generate_report",
            framework=framework,
            assessment_count=len(assessments),
        )
        total = len(assessments)
        compliant = sum(1 for a in assessments if a.status == ControlStatus.COMPLIANT)
        partial = sum(1 for a in assessments if a.status == ControlStatus.PARTIALLY_COMPLIANT)
        non_compliant = sum(1 for a in assessments if a.status == ControlStatus.NON_COMPLIANT)
        not_applicable = sum(1 for a in assessments if a.status == ControlStatus.NOT_APPLICABLE)

        applicable = total - not_applicable
        score = round((compliant + partial * 0.5) / applicable, 4) if applicable > 0 else 0.0

        framework_label = framework.upper().replace("_", " ")
        summary_parts = [
            f"{framework_label} Compliance Report for period {period_start} to {period_end}.",
            f"Assessed {total} controls: {compliant} compliant, "
            f"{partial} partially compliant, {non_compliant} non-compliant.",
            f"Overall compliance score: {score * 100:.1f}%.",
        ]
        if non_compliant > 0:
            summary_parts.append(
                f"Immediate attention required for {non_compliant} non-compliant controls."
            )

        return ComplianceReport(
            id=f"rpt-{framework}-{uuid.uuid4().hex[:8]}",
            framework=framework,
            report_title=f"{framework_label} Compliance Report",
            period_start=period_start,
            period_end=period_end,
            total_controls=total,
            compliant_count=compliant,
            partially_compliant_count=partial,
            non_compliant_count=non_compliant,
            compliance_score=score,
            executive_summary=" ".join(summary_parts),
            control_assessments=[a.model_dump() for a in assessments],
            generated_at=time.time(),
        )

    async def package_artifacts(
        self,
        report: ComplianceReport,
        evidence: list[EvidenceItem],
    ) -> ArtifactPackage:
        """Create an evidence package with integrity hashes."""
        logger.info(
            "compliance_reporter.package_artifacts",
            report_id=report.id,
            evidence_count=len(evidence),
        )
        # Compute package hash from all evidence digests
        combined = "|".join(sorted(e.hash_digest for e in evidence if e.hash_digest))
        package_hash = hashlib.sha256(combined.encode()).hexdigest()

        # Estimate size (mock: ~0.5MB per artifact)
        total_size = round(len(evidence) * 0.5, 2)

        return ArtifactPackage(
            id=f"pkg-{report.id}-{uuid.uuid4().hex[:8]}",
            report_id=report.id,
            package_path=f"/packages/{report.framework}/{report.id}.zip",
            total_artifacts=len(evidence),
            total_size_mb=total_size,
            hash_digest=package_hash,
            created_at=time.time(),
        )

    async def deliver_report(
        self,
        report: ComplianceReport,
        recipients: list[str],
    ) -> list[DeliveryResult]:
        """Deliver report and evidence package to stakeholders."""
        logger.info(
            "compliance_reporter.deliver_report",
            report_id=report.id,
            recipient_count=len(recipients),
        )
        if self._delivery_service is not None:
            try:
                raw = await self._delivery_service.deliver(
                    report_id=report.id, recipients=recipients
                )
                return [DeliveryResult(**r) for r in raw]
            except Exception:
                logger.exception("compliance_reporter.deliver_report.error")
                return []

        now = time.time()
        results: list[DeliveryResult] = []
        for recipient in recipients:
            # Determine delivery method from recipient format
            if "@" in recipient:
                method = "email"
            elif recipient.startswith("#"):
                method = "slack"
            elif recipient.startswith("s3://"):
                method = "s3_upload"
            else:
                method = "webhook"

            results.append(
                DeliveryResult(
                    id=f"dlv-{uuid.uuid4().hex[:8]}",
                    report_id=report.id,
                    recipient=recipient,
                    delivery_method=method,
                    delivered_at=now,
                    success=True,
                )
            )
        return results
