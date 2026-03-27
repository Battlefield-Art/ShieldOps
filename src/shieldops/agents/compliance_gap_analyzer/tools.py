"""Compliance Gap Analyzer Agent — Tool functions."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from .models import (
    ComplianceGap,
    ControlStatus,
    CoverageAssessment,
    Framework,
    FrameworkMapping,
    RemediationPlan,
    SecurityControl,
)

logger = structlog.get_logger()

# Representative framework requirements
_FRAMEWORK_REQS: dict[Framework, list[dict[str, str]]] = {
    Framework.SOC2: [
        {"id": "CC6.1", "name": "Logical Access"},
        {"id": "CC6.2", "name": "System Access Auth"},
        {"id": "CC6.3", "name": "Role-Based Access"},
        {"id": "CC7.1", "name": "Detect Anomalies"},
        {"id": "CC7.2", "name": "Monitor Components"},
        {"id": "CC8.1", "name": "Change Management"},
    ],
    Framework.HIPAA: [
        {"id": "164.312(a)", "name": "Access Control"},
        {"id": "164.312(b)", "name": "Audit Controls"},
        {"id": "164.312(c)", "name": "Integrity"},
        {"id": "164.312(d)", "name": "Authentication"},
        {"id": "164.312(e)", "name": "Transmission"},
    ],
    Framework.PCI_DSS: [
        {"id": "1.1", "name": "Firewall Config"},
        {"id": "2.1", "name": "Default Passwords"},
        {"id": "3.1", "name": "Stored Card Data"},
        {"id": "6.1", "name": "Vulnerability Mgmt"},
        {"id": "8.1", "name": "User Identification"},
        {"id": "10.1", "name": "Audit Trails"},
    ],
    Framework.NIST_CSF: [
        {"id": "ID.AM-1", "name": "Asset Inventory"},
        {"id": "PR.AC-1", "name": "Access Mgmt"},
        {"id": "DE.CM-1", "name": "Network Monitor"},
        {"id": "RS.RP-1", "name": "Response Plan"},
        {"id": "RC.RP-1", "name": "Recovery Plan"},
    ],
}

# Representative controls
_BASELINE_CONTROLS: list[dict[str, Any]] = [
    {
        "name": "MFA Enforcement",
        "cat": "identity",
        "status": "implemented",
    },
    {
        "name": "RBAC Policy",
        "cat": "access",
        "status": "implemented",
    },
    {
        "name": "Encryption at Rest",
        "cat": "data",
        "status": "implemented",
    },
    {
        "name": "SIEM Monitoring",
        "cat": "detection",
        "status": "partial",
    },
    {
        "name": "Incident Response Plan",
        "cat": "response",
        "status": "partial",
    },
    {
        "name": "Change Management",
        "cat": "operations",
        "status": "implemented",
    },
    {
        "name": "Vulnerability Scanning",
        "cat": "security",
        "status": "partial",
    },
    {
        "name": "Data Classification",
        "cat": "data",
        "status": "missing",
    },
    {
        "name": "Backup and Recovery",
        "cat": "operations",
        "status": "implemented",
    },
    {
        "name": "Security Awareness",
        "cat": "people",
        "status": "partial",
    },
]


class ComplianceGapAnalyzerToolkit:
    """Toolkit for compliance gap analysis."""

    def __init__(
        self,
        compliance_db: Any | None = None,
        control_registry: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._compliance_db = compliance_db
        self._control_registry = control_registry
        self._repository = repository

    async def inventory_controls(
        self,
        tenant_id: str,
    ) -> list[SecurityControl]:
        """Collect security controls inventory."""
        logger.info(
            "compliance_gap.inventory_controls",
            tenant_id=tenant_id,
        )
        if self._control_registry is not None:
            try:
                return await self._control_registry.list(
                    tenant_id,
                )
            except Exception:
                logger.warning(
                    "compliance_gap.registry_fallback",
                )

        return [
            SecurityControl(
                id=f"ctrl-{uuid4().hex[:8]}",
                name=c["name"],
                category=c["cat"],
                status=ControlStatus(c["status"]),
                owner="security-team",
            )
            for c in _BASELINE_CONTROLS
        ]

    async def map_to_frameworks(
        self,
        controls: list[SecurityControl],
        frameworks: list[Framework],
    ) -> list[FrameworkMapping]:
        """Map controls to framework requirements."""
        logger.info(
            "compliance_gap.map_to_frameworks",
            control_count=len(controls),
            framework_count=len(frameworks),
        )
        mappings: list[FrameworkMapping] = []
        for fw in frameworks:
            reqs = _FRAMEWORK_REQS.get(fw, [])
            for i, req in enumerate(reqs):
                # Map controls round-robin
                ctrl = controls[i % len(controls)] if controls else None
                status = ctrl.status if ctrl else ControlStatus.MISSING
                mappings.append(
                    FrameworkMapping(
                        control_id=(ctrl.id if ctrl else ""),
                        framework=fw,
                        requirement_id=req["id"],
                        requirement_name=req["name"],
                        status=status,
                        gap_description=(
                            "" if status == ControlStatus.IMPLEMENTED else f"Gap in {req['name']}"
                        ),
                    )
                )
        return mappings

    async def assess_coverage(
        self,
        mappings: list[FrameworkMapping],
    ) -> list[CoverageAssessment]:
        """Assess coverage per framework."""
        logger.info(
            "compliance_gap.assess_coverage",
            mapping_count=len(mappings),
        )
        fw_groups: dict[Framework, list[FrameworkMapping]] = {}
        for m in mappings:
            fw_groups.setdefault(
                m.framework,
                [],
            ).append(m)

        assessments: list[CoverageAssessment] = []
        for fw, maps in fw_groups.items():
            total = len(maps)
            impl = sum(1 for m in maps if m.status == ControlStatus.IMPLEMENTED)
            partial = sum(1 for m in maps if m.status == ControlStatus.PARTIAL)
            missing = sum(1 for m in maps if m.status == ControlStatus.MISSING)
            na = sum(1 for m in maps if m.status == ControlStatus.NOT_APPLICABLE)
            applicable = total - na
            pct = (
                round(
                    (impl + partial * 0.5) / applicable * 100,
                    1,
                )
                if applicable
                else 0.0
            )

            assessments.append(
                CoverageAssessment(
                    framework=fw,
                    total_requirements=total,
                    implemented=impl,
                    partial=partial,
                    missing=missing,
                    not_applicable=na,
                    coverage_pct=pct,
                )
            )
        return assessments

    async def identify_gaps(
        self,
        mappings: list[FrameworkMapping],
    ) -> list[ComplianceGap]:
        """Identify compliance gaps."""
        logger.info(
            "compliance_gap.identify_gaps",
            mapping_count=len(mappings),
        )
        gaps: list[ComplianceGap] = []
        for m in mappings:
            if m.status in (
                ControlStatus.MISSING,
                ControlStatus.PARTIAL,
            ):
                risk = "critical" if m.status == ControlStatus.MISSING else "high"
                gaps.append(
                    ComplianceGap(
                        framework=m.framework,
                        requirement_id=(m.requirement_id),
                        requirement_name=(m.requirement_name),
                        current_status=m.status,
                        risk_level=risk,
                        remediation_priority=risk,
                        estimated_effort="medium",
                    )
                )
        return gaps

    async def generate_remediation_plans(
        self,
        gaps: list[ComplianceGap],
    ) -> list[RemediationPlan]:
        """Generate remediation plans for gaps."""
        logger.info(
            "compliance_gap.remediation_plans",
            gap_count=len(gaps),
        )
        plans: list[RemediationPlan] = []
        for gap in gaps:
            plans.append(
                RemediationPlan(
                    gap_id=f"rem-{uuid4().hex[:8]}",
                    framework=gap.framework,
                    requirement_id=(gap.requirement_id),
                    action_items=[
                        f"Implement {gap.requirement_name}",
                        "Document evidence",
                        "Validate with auditor",
                    ],
                    owner="security-team",
                    timeline="30-60 days",
                    estimated_cost="$10K-$50K",
                    priority=gap.remediation_priority,
                )
            )
        return plans
