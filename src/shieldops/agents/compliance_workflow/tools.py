"""Compliance Workflow Agent — Tool functions."""

from __future__ import annotations

import hashlib
import time
from typing import Any

import structlog

from .models import (
    ComplianceControl,
    ComplianceFramework,
    ComplianceGap,
    ControlStatus,
    EvidenceItem,
    FrameworkMapping,
    RemediationAction,
)

logger = structlog.get_logger()

# ── Mock control definitions per framework ─────────

_FRAMEWORK_CONTROLS: dict[str, list[dict[str, str]]] = {
    "soc2": [
        {
            "control_id": "SOC2-CC1.1",
            "title": "Control Environment",
            "description": "Commitment to integrity",
            "category": "Common Criteria",
        },
        {
            "control_id": "SOC2-CC5.1",
            "title": "Risk Assessment",
            "description": "Identifies and assesses risks",
            "category": "Common Criteria",
        },
        {
            "control_id": "SOC2-CC6.1",
            "title": "Logical Access Controls",
            "description": "Restricts logical access",
            "category": "Common Criteria",
        },
        {
            "control_id": "SOC2-CC6.2",
            "title": "Authentication Mechanisms",
            "description": "Authenticates users",
            "category": "Common Criteria",
        },
        {
            "control_id": "SOC2-CC7.1",
            "title": "System Monitoring",
            "description": "Monitors system components",
            "category": "Common Criteria",
        },
        {
            "control_id": "SOC2-CC7.2",
            "title": "Incident Response",
            "description": "Responds to incidents",
            "category": "Common Criteria",
        },
        {
            "control_id": "SOC2-CC8.1",
            "title": "Change Management",
            "description": "Manages infrastructure changes",
            "category": "Common Criteria",
        },
    ],
    "hipaa": [
        {
            "control_id": "HIPAA-164.308a1",
            "title": "Security Management Process",
            "description": "Risk analysis and management",
            "category": "Administrative Safeguards",
        },
        {
            "control_id": "HIPAA-164.308a3",
            "title": "Workforce Security",
            "description": "Authorization and supervision",
            "category": "Administrative Safeguards",
        },
        {
            "control_id": "HIPAA-164.310a1",
            "title": "Facility Access Controls",
            "description": "Physical access safeguards",
            "category": "Physical Safeguards",
        },
        {
            "control_id": "HIPAA-164.312a1",
            "title": "Access Control",
            "description": "Unique user identification",
            "category": "Technical Safeguards",
        },
        {
            "control_id": "HIPAA-164.312b",
            "title": "Audit Controls",
            "description": "Activity logging mechanisms",
            "category": "Technical Safeguards",
        },
        {
            "control_id": "HIPAA-164.312e1",
            "title": "Transmission Security",
            "description": "Encryption of ePHI in transit",
            "category": "Technical Safeguards",
        },
    ],
    "pci_dss": [
        {
            "control_id": "PCI-1.1",
            "title": "Network Security Controls",
            "description": "Install and maintain firewalls",
            "category": "Build Secure Network",
        },
        {
            "control_id": "PCI-2.1",
            "title": "Secure Configurations",
            "description": "No vendor-supplied defaults",
            "category": "Build Secure Network",
        },
        {
            "control_id": "PCI-3.1",
            "title": "Protect Stored Data",
            "description": "Protect stored cardholder data",
            "category": "Protect Data",
        },
        {
            "control_id": "PCI-6.1",
            "title": "Secure Systems",
            "description": "Develop and maintain securely",
            "category": "Vulnerability Management",
        },
        {
            "control_id": "PCI-8.1",
            "title": "Identify and Authenticate",
            "description": "Identify users, authenticate",
            "category": "Access Control",
        },
        {
            "control_id": "PCI-10.1",
            "title": "Logging and Monitoring",
            "description": "Log and monitor all access",
            "category": "Monitoring",
        },
    ],
    "gdpr": [
        {
            "control_id": "GDPR-Art5",
            "title": "Processing Principles",
            "description": "Lawfulness, fairness",
            "category": "Principles",
        },
        {
            "control_id": "GDPR-Art25",
            "title": "Data Protection by Design",
            "description": "Privacy by design and default",
            "category": "Controller Obligations",
        },
        {
            "control_id": "GDPR-Art30",
            "title": "Records of Processing",
            "description": "Maintain processing records",
            "category": "Controller Obligations",
        },
        {
            "control_id": "GDPR-Art32",
            "title": "Security of Processing",
            "description": "Appropriate technical measures",
            "category": "Security",
        },
        {
            "control_id": "GDPR-Art33",
            "title": "Breach Notification",
            "description": "Notify authority in 72 hours",
            "category": "Breach Response",
        },
        {
            "control_id": "GDPR-Art35",
            "title": "Impact Assessment",
            "description": "Data protection impact assessment",
            "category": "Risk Assessment",
        },
    ],
    "iso_27001": [
        {
            "control_id": "ISO-A5",
            "title": "Information Security Policies",
            "description": "Management direction",
            "category": "Organizational Controls",
        },
        {
            "control_id": "ISO-A6",
            "title": "Organization of InfoSec",
            "description": "Internal organization",
            "category": "Organizational Controls",
        },
        {
            "control_id": "ISO-A8",
            "title": "Asset Management",
            "description": "Identify and classify assets",
            "category": "Asset Management",
        },
        {
            "control_id": "ISO-A9",
            "title": "Access Control",
            "description": "Limit access to information",
            "category": "Access Control",
        },
        {
            "control_id": "ISO-A12",
            "title": "Operations Security",
            "description": "Operational procedures",
            "category": "Operations",
        },
        {
            "control_id": "ISO-A18",
            "title": "Compliance",
            "description": "Legal and contractual",
            "category": "Compliance",
        },
    ],
    "nist_csf": [
        {
            "control_id": "NIST-ID.AM",
            "title": "Asset Management",
            "description": "Identify and manage assets",
            "category": "Identify",
        },
        {
            "control_id": "NIST-PR.AC",
            "title": "Access Control",
            "description": "Manage access permissions",
            "category": "Protect",
        },
        {
            "control_id": "NIST-DE.CM",
            "title": "Continuous Monitoring",
            "description": "Monitor for anomalies",
            "category": "Detect",
        },
        {
            "control_id": "NIST-RS.RP",
            "title": "Response Planning",
            "description": "Execute response processes",
            "category": "Respond",
        },
        {
            "control_id": "NIST-RC.RP",
            "title": "Recovery Planning",
            "description": "Execute recovery processes",
            "category": "Recover",
        },
    ],
    "fedramp": [
        {
            "control_id": "FED-AC-2",
            "title": "Account Management",
            "description": "Manage system accounts",
            "category": "Access Control",
        },
        {
            "control_id": "FED-AU-2",
            "title": "Audit Events",
            "description": "Auditable event identification",
            "category": "Audit",
        },
        {
            "control_id": "FED-CM-6",
            "title": "Configuration Settings",
            "description": "Establish config settings",
            "category": "Configuration",
        },
        {
            "control_id": "FED-IA-2",
            "title": "User Identification",
            "description": "Identify and authenticate",
            "category": "Identification",
        },
        {
            "control_id": "FED-SC-7",
            "title": "Boundary Protection",
            "description": "Monitor and control comms",
            "category": "System Protection",
        },
    ],
}

# Status rotation for realistic mock output
_STATUS_ROTATION = [
    ControlStatus.COMPLIANT,
    ControlStatus.COMPLIANT,
    ControlStatus.PARTIALLY_COMPLIANT,
    ControlStatus.COMPLIANT,
    ControlStatus.NON_COMPLIANT,
    ControlStatus.COMPLIANT,
    ControlStatus.PARTIALLY_COMPLIANT,
]

# ── Evidence templates ─────────────────────────────

_EVIDENCE_SOURCES: dict[str, list[dict[str, str]]] = {
    "access_control": [
        {
            "source": "iam_policy_export",
            "description": "IAM policy configuration",
        },
        {
            "source": "sso_config",
            "description": "SSO/MFA configuration snapshot",
        },
    ],
    "monitoring": [
        {
            "source": "cloudwatch_config",
            "description": "CloudWatch alarm configs",
        },
        {
            "source": "siem_rules",
            "description": "SIEM detection rule inventory",
        },
    ],
    "encryption": [
        {
            "source": "kms_key_inventory",
            "description": "KMS encryption key inventory",
        },
        {
            "source": "tls_cert_scan",
            "description": "TLS certificate scan results",
        },
    ],
    "default": [
        {
            "source": "config_snapshot",
            "description": "System configuration snapshot",
        },
        {
            "source": "audit_log",
            "description": "Audit log extract for period",
        },
    ],
}


def _evidence_category(control_id: str) -> str:
    """Determine evidence category from control ID."""
    cid = control_id.lower()
    if any(k in cid for k in ("ac", "a9", "6.1", "8.1", "ia")):
        return "access_control"
    if any(k in cid for k in ("7.1", "de.cm", "au", "10.1")):
        return "monitoring"
    if any(k in cid for k in ("312e", "3.1", "32", "sc")):
        return "encryption"
    return "default"


class ComplianceWorkflowToolkit:
    """Tools for compliance workflow automation."""

    def __init__(
        self,
        compliance_backend: Any | None = None,
        evidence_store: Any | None = None,
    ) -> None:
        self._backend = compliance_backend
        self._evidence_store = evidence_store

    async def identify_frameworks(
        self,
        tenant_id: str,
    ) -> list[FrameworkMapping]:
        """Identify applicable frameworks for a tenant."""
        logger.info(
            "compliance_workflow.identify_frameworks",
            tenant_id=tenant_id,
        )
        if self._backend is not None:
            try:
                raw = await self._backend.identify(
                    tenant_id=tenant_id,
                )
                return [FrameworkMapping(**r) for r in raw]
            except Exception:
                logger.exception(
                    "compliance_workflow.identify.error",
                )
                return []

        # Mock: return common frameworks
        return [
            FrameworkMapping(
                framework=ComplianceFramework.SOC2,
                applicable=True,
                reason="SaaS platform with customer data",
                control_count=7,
                priority=1,
            ),
            FrameworkMapping(
                framework=ComplianceFramework.HIPAA,
                applicable=True,
                reason="Healthcare customer ePHI",
                control_count=6,
                priority=2,
            ),
            FrameworkMapping(
                framework=ComplianceFramework.GDPR,
                applicable=True,
                reason="EU customer personal data",
                control_count=6,
                priority=3,
            ),
            FrameworkMapping(
                framework=ComplianceFramework.ISO_27001,
                applicable=True,
                reason="Enterprise security certification",
                control_count=6,
                priority=4,
            ),
        ]

    async def map_controls(
        self,
        frameworks: list[FrameworkMapping],
    ) -> list[ComplianceControl]:
        """Map controls for identified frameworks."""
        logger.info(
            "compliance_workflow.map_controls",
            framework_count=len(frameworks),
        )
        if self._backend is not None:
            try:
                raw = await self._backend.map_controls(
                    frameworks=[f.model_dump() for f in frameworks],
                )
                return [ComplianceControl(**r) for r in raw]
            except Exception:
                logger.exception(
                    "compliance_workflow.map.error",
                )
                return []

        controls: list[ComplianceControl] = []
        for fm in frameworks:
            fw_key = fm.framework.value
            defs = _FRAMEWORK_CONTROLS.get(fw_key, [])
            for i, ctrl_def in enumerate(defs):
                status = _STATUS_ROTATION[i % len(_STATUS_ROTATION)]
                controls.append(
                    ComplianceControl(
                        control_id=ctrl_def["control_id"],
                        framework=fm.framework,
                        title=ctrl_def["title"],
                        description=ctrl_def["description"],
                        category=ctrl_def["category"],
                        status=status,
                        evidence_required=[
                            "config_snapshot",
                            "audit_log",
                        ],
                    )
                )
        return controls

    async def collect_evidence(
        self,
        controls: list[ComplianceControl],
    ) -> list[EvidenceItem]:
        """Collect evidence for each control."""
        logger.info(
            "compliance_workflow.collect_evidence",
            control_count=len(controls),
        )
        if self._evidence_store is not None:
            try:
                raw = await self._evidence_store.collect(
                    control_ids=[c.control_id for c in controls],
                )
                return [EvidenceItem(**r) for r in raw]
            except Exception:
                logger.exception(
                    "compliance_workflow.evidence.error",
                )
                return []

        evidence: list[EvidenceItem] = []
        now = time.time()
        for ctrl in controls:
            cat = _evidence_category(ctrl.control_id)
            sources = _EVIDENCE_SOURCES.get(cat, [])
            for src in sources:
                eid = hashlib.sha256(f"{ctrl.control_id}:{src['source']}".encode()).hexdigest()[:12]
                evidence.append(
                    EvidenceItem(
                        evidence_id=f"EV-{eid}",
                        control_id=ctrl.control_id,
                        source=src["source"],
                        description=src["description"],
                        collected_at=now,
                        valid=True,
                        content_hash=eid,
                    )
                )
        return evidence

    async def assess_gaps(
        self,
        controls: list[ComplianceControl],
        evidence: list[EvidenceItem],
    ) -> list[ComplianceGap]:
        """Assess compliance gaps."""
        logger.info(
            "compliance_workflow.assess_gaps",
            control_count=len(controls),
            evidence_count=len(evidence),
        )
        evidence_map: dict[str, list[EvidenceItem]] = {}
        for ev in evidence:
            evidence_map.setdefault(
                ev.control_id,
                [],
            ).append(ev)

        gaps: list[ComplianceGap] = []
        for ctrl in controls:
            if ctrl.status in (
                ControlStatus.NON_COMPLIANT,
                ControlStatus.PARTIALLY_COMPLIANT,
            ):
                has_ev = bool(evidence_map.get(ctrl.control_id))
                severity = "critical" if ctrl.status == ControlStatus.NON_COMPLIANT else "high"
                risk = 0.9 if ctrl.status == ControlStatus.NON_COMPLIANT else 0.6
                root = "Missing implementation" if not has_ev else "Partial implementation"
                gid = f"GAP-{ctrl.control_id}"
                gaps.append(
                    ComplianceGap(
                        gap_id=gid,
                        control_id=ctrl.control_id,
                        framework=ctrl.framework,
                        severity=severity,
                        description=(f"{ctrl.title}: {ctrl.description} — {ctrl.status.value}"),
                        root_cause=root,
                        risk_score=risk,
                    )
                )
        return gaps

    async def generate_remediation(
        self,
        gaps: list[ComplianceGap],
    ) -> list[RemediationAction]:
        """Generate remediation actions for gaps."""
        logger.info(
            "compliance_workflow.generate_remediation",
            gap_count=len(gaps),
        )
        actions: list[RemediationAction] = []
        for i, gap in enumerate(gaps):
            effort = "high" if gap.severity == "critical" else "medium"
            days = 14 if gap.severity == "critical" else 7
            actions.append(
                RemediationAction(
                    action_id=f"REM-{i + 1:03d}",
                    gap_id=gap.gap_id,
                    control_id=gap.control_id,
                    title=(f"Remediate {gap.control_id}"),
                    description=(
                        f"Address: {gap.root_cause}. Implement controls for {gap.description}"
                    ),
                    effort=effort,
                    priority=i + 1,
                    estimated_days=days,
                    owner="security-team",
                )
            )
        return actions
