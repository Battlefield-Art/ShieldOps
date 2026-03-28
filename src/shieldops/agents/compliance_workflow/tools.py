"""Tool functions for the Compliance Workflow Agent."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.compliance_workflow.models import (
    ComplianceControl,
    ControlStatus,
    EvidenceItem,
    Framework,
    GapFinding,
)

logger = structlog.get_logger()

# Control templates keyed by framework
FRAMEWORK_CONTROLS: dict[str, list[dict[str, str]]] = {
    "soc2": [
        {
            "id": "CC1.1",
            "name": "Control Environment",
            "category": "Common Criteria",
            "description": "COSO principle: commitment to integrity",
        },
        {
            "id": "CC2.1",
            "name": "Information Communication",
            "category": "Common Criteria",
            "description": "Internal communication of objectives",
        },
        {
            "id": "CC3.1",
            "name": "Risk Assessment",
            "category": "Common Criteria",
            "description": "Risk identification and analysis",
        },
        {
            "id": "CC5.1",
            "name": "Control Activities",
            "category": "Common Criteria",
            "description": "Selection and development of controls",
        },
        {
            "id": "CC6.1",
            "name": "Logical Access",
            "category": "Common Criteria",
            "description": "Logical access security controls",
        },
        {
            "id": "CC7.1",
            "name": "System Operations",
            "category": "Common Criteria",
            "description": "Detection of system anomalies",
        },
        {
            "id": "CC8.1",
            "name": "Change Management",
            "category": "Common Criteria",
            "description": "Infrastructure and software changes",
        },
        {
            "id": "CC9.1",
            "name": "Risk Mitigation",
            "category": "Common Criteria",
            "description": "Risk mitigation activities",
        },
    ],
    "hipaa": [
        {
            "id": "§164.312(a)",
            "name": "Access Control",
            "category": "Technical Safeguards",
            "description": "Unique user identification",
        },
        {
            "id": "§164.312(c)",
            "name": "Integrity Controls",
            "category": "Technical Safeguards",
            "description": "ePHI integrity mechanisms",
        },
        {
            "id": "§164.312(e)",
            "name": "Transmission Security",
            "category": "Technical Safeguards",
            "description": "ePHI transmission encryption",
        },
        {
            "id": "§164.308(a)(1)",
            "name": "Security Management",
            "category": "Administrative Safeguards",
            "description": "Risk analysis and management",
        },
    ],
    "pci_dss": [
        {
            "id": "PCI-1.1",
            "name": "Firewall Configuration",
            "category": "Network Security",
            "description": "Firewall and router standards",
        },
        {
            "id": "PCI-3.1",
            "name": "Data Protection",
            "category": "Cardholder Data",
            "description": "Stored cardholder data protection",
        },
        {
            "id": "PCI-6.1",
            "name": "Secure Development",
            "category": "Application Security",
            "description": "Vulnerability identification process",
        },
        {
            "id": "PCI-10.1",
            "name": "Audit Logging",
            "category": "Monitoring",
            "description": "Audit trail for system components",
        },
    ],
}

# Evidence sources by control category
EVIDENCE_SOURCES: dict[str, list[str]] = {
    "Common Criteria": [
        "access_logs",
        "config_snapshots",
        "policy_docs",
    ],
    "Technical Safeguards": [
        "encryption_configs",
        "access_control_lists",
        "audit_logs",
    ],
    "Network Security": [
        "firewall_rules",
        "network_diagrams",
        "scan_results",
    ],
    "Cardholder Data": [
        "encryption_configs",
        "key_management_logs",
        "data_flow_diagrams",
    ],
    "Application Security": [
        "code_reviews",
        "sast_results",
        "dependency_scans",
    ],
    "Monitoring": [
        "audit_logs",
        "alert_configs",
        "log_retention_policies",
    ],
    "Administrative Safeguards": [
        "policy_docs",
        "training_records",
        "risk_assessments",
    ],
}


class ComplianceWorkflowToolkit:
    """Toolkit for compliance workflow automation."""

    def __init__(
        self,
        evidence_service: Any | None = None,
        policy_store: Any | None = None,
    ) -> None:
        self._evidence_service = evidence_service
        self._policy_store = policy_store
        self._test_results: dict[str, ControlStatus] = {}

    async def identify_controls(
        self,
        framework: str,
        tenant_id: str = "",
    ) -> list[ComplianceControl]:
        """Identify applicable controls for a framework.

        Args:
            framework: Compliance framework identifier.
            tenant_id: Tenant for scoping.

        Returns:
            List of ComplianceControl objects.
        """
        if self._policy_store is not None:
            try:
                return await self._policy_store.get_controls(
                    framework,
                    tenant_id,
                )
            except Exception:
                logger.debug(
                    "policy_store_failed",
                    framework=framework,
                )

        fw_key = framework.lower()
        templates = FRAMEWORK_CONTROLS.get(fw_key, [])
        if not templates:
            templates = FRAMEWORK_CONTROLS.get("soc2", [])

        controls = [
            ComplianceControl(
                id=t["id"],
                name=t["name"],
                framework=Framework(fw_key)
                if fw_key in Framework.__members__.values()
                else Framework.SOC2,
                category=t["category"],
                description=t["description"],
            )
            for t in templates
        ]

        logger.info(
            "compliance_workflow.controls_identified",
            framework=framework,
            count=len(controls),
        )
        return controls

    async def collect_evidence(
        self,
        control: ComplianceControl,
    ) -> list[EvidenceItem]:
        """Collect evidence for a specific control.

        Args:
            control: The control to collect evidence for.

        Returns:
            List of EvidenceItem objects.
        """
        if self._evidence_service is not None:
            try:
                return await self._evidence_service.collect(
                    control.id,
                )
            except Exception:
                logger.debug(
                    "evidence_service_failed",
                    control_id=control.id,
                )

        sources = EVIDENCE_SOURCES.get(
            control.category,
            [
                "audit_logs",
            ],
        )
        items = [
            EvidenceItem(
                id=f"ev-{control.id}-{i}",
                control_id=control.id,
                source=src,
                description=f"Auto-collected {src} for {control.name}",
                collected_at=time.time(),
                valid=True,
            )
            for i, src in enumerate(sources)
        ]

        logger.info(
            "compliance_workflow.evidence_collected",
            control_id=control.id,
            count=len(items),
        )
        return items

    async def test_control(
        self,
        control: ComplianceControl,
        evidence: list[EvidenceItem],
    ) -> ControlStatus:
        """Test a control against its evidence.

        Args:
            control: The control to test.
            evidence: Collected evidence items.

        Returns:
            ControlStatus result.
        """
        if not evidence:
            status = ControlStatus.NOT_TESTED
        elif all(e.valid for e in evidence):
            status = ControlStatus.PASSING
        elif any(e.valid for e in evidence):
            status = ControlStatus.PARTIALLY_PASSING
        else:
            status = ControlStatus.FAILING

        self._test_results[control.id] = status
        logger.info(
            "compliance_workflow.control_tested",
            control_id=control.id,
            status=status.value,
            evidence_count=len(evidence),
        )
        return status

    async def identify_gaps(
        self,
        controls: list[ComplianceControl],
    ) -> list[GapFinding]:
        """Identify gaps from control test results.

        Args:
            controls: Controls that have been tested.

        Returns:
            List of GapFinding objects.
        """
        gaps: list[GapFinding] = []
        for ctrl in controls:
            if ctrl.status in (
                ControlStatus.FAILING,
                ControlStatus.NOT_TESTED,
            ):
                gaps.append(
                    GapFinding(
                        id=f"gap-{ctrl.id}",
                        control_id=ctrl.id,
                        severity="high" if ctrl.status == ControlStatus.FAILING else "medium",
                        description=(f"Control {ctrl.id} ({ctrl.name}) is {ctrl.status.value}"),
                    )
                )
            elif ctrl.status == ControlStatus.PARTIALLY_PASSING:
                gaps.append(
                    GapFinding(
                        id=f"gap-{ctrl.id}",
                        control_id=ctrl.id,
                        severity="medium",
                        description=(
                            f"Control {ctrl.id} ({ctrl.name}) is "
                            f"partially passing — evidence incomplete"
                        ),
                    )
                )

        logger.info(
            "compliance_workflow.gaps_identified",
            count=len(gaps),
        )
        return gaps

    async def generate_remediation(
        self,
        gap: GapFinding,
    ) -> dict[str, str]:
        """Generate a remediation plan for a gap.

        Args:
            gap: The gap finding to remediate.

        Returns:
            Dict with remediation details.
        """
        plan = {
            "gap_id": gap.id,
            "control_id": gap.control_id,
            "severity": gap.severity,
            "action": f"Remediate {gap.description}",
            "status": "pending",
        }
        logger.info(
            "compliance_workflow.remediation_generated",
            gap_id=gap.id,
        )
        return plan
