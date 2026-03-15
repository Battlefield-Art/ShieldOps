"""Compliance Auditor Agent — Tool functions for compliance scanning and evidence collection."""

from __future__ import annotations

import time
from typing import Any

import structlog

logger = structlog.get_logger()

# Default control definitions per framework
_FRAMEWORK_CONTROLS: dict[str, list[dict[str, str]]] = {
    "soc2": [
        {"control_id": "SOC2-CC6.1", "description": "Logical and physical access controls"},
        {"control_id": "SOC2-CC6.2", "description": "User authentication mechanisms"},
        {"control_id": "SOC2-CC7.1", "description": "System monitoring and anomaly detection"},
        {"control_id": "SOC2-CC7.2", "description": "Incident response procedures"},
        {"control_id": "SOC2-CC8.1", "description": "Change management controls"},
    ],
    "pci_dss": [
        {"control_id": "PCI-1.1", "description": "Install and maintain network security controls"},
        {"control_id": "PCI-2.1", "description": "Apply secure configurations"},
        {"control_id": "PCI-3.1", "description": "Protect stored account data"},
        {"control_id": "PCI-6.1", "description": "Develop and maintain secure systems"},
        {"control_id": "PCI-8.1", "description": "Identify users and authenticate access"},
    ],
    "hipaa": [
        {"control_id": "HIPAA-164.312a", "description": "Access control — unique user ID"},
        {"control_id": "HIPAA-164.312b", "description": "Audit controls — activity logging"},
        {"control_id": "HIPAA-164.312c", "description": "Integrity controls — ePHI protection"},
        {"control_id": "HIPAA-164.312d", "description": "Person authentication"},
        {"control_id": "HIPAA-164.312e", "description": "Transmission security — encryption"},
    ],
    "gdpr": [
        {"control_id": "GDPR-Art25", "description": "Data protection by design and default"},
        {"control_id": "GDPR-Art30", "description": "Records of processing activities"},
        {"control_id": "GDPR-Art32", "description": "Security of processing"},
        {"control_id": "GDPR-Art33", "description": "Breach notification to authority"},
        {"control_id": "GDPR-Art35", "description": "Data protection impact assessment"},
    ],
    "iso27001": [
        {"control_id": "ISO-A5", "description": "Information security policies"},
        {"control_id": "ISO-A6", "description": "Organization of information security"},
        {"control_id": "ISO-A8", "description": "Asset management"},
        {"control_id": "ISO-A9", "description": "Access control"},
        {"control_id": "ISO-A12", "description": "Operations security"},
    ],
}


class ComplianceAuditorToolkit:
    """Tools for compliance scanning, evidence collection, and gap analysis."""

    def __init__(
        self,
        compliance_backend: Any | None = None,
        evidence_store: Any | None = None,
    ) -> None:
        self._compliance_backend = compliance_backend
        self._evidence_store = evidence_store

    async def scan_controls(
        self,
        framework: str,
    ) -> list[dict[str, Any]]:
        """Scan infrastructure for control compliance against a framework."""
        logger.info("compliance_auditor.scan_controls", framework=framework)
        if self._compliance_backend is not None:
            try:
                return await self._compliance_backend.scan(framework=framework)
            except Exception:
                logger.exception("compliance_auditor.scan_controls.error")
                return []

        # Mock: return default controls with heuristic statuses
        controls = _FRAMEWORK_CONTROLS.get(framework, [])
        results: list[dict[str, Any]] = []
        for i, ctrl in enumerate(controls):
            # Alternate statuses for realistic mock output
            if i % 4 == 0:
                status = "compliant"
            elif i % 4 == 1:
                status = "non_compliant"
            elif i % 4 == 2:
                status = "partial"
            else:
                status = "compliant"
            results.append(
                {
                    "control_id": ctrl["control_id"],
                    "framework": framework,
                    "description": ctrl["description"],
                    "status": status,
                    "gaps": ["Missing documentation"] if status == "non_compliant" else [],
                }
            )
        return results

    async def collect_evidence(
        self,
        control_id: str,
    ) -> list[dict[str, Any]]:
        """Gather evidence artifacts for a specific control."""
        logger.info("compliance_auditor.collect_evidence", control_id=control_id)
        if self._evidence_store is not None:
            try:
                return await self._evidence_store.collect(control_id=control_id)
            except Exception:
                logger.exception("compliance_auditor.collect_evidence.error")
                return []

        # Mock evidence
        now = time.time()
        return [
            {
                "id": f"ev-{control_id}-001",
                "source": "infrastructure_scan",
                "description": f"Automated scan result for {control_id}",
                "collected_at": now,
                "valid_until": now + 86400 * 90,  # 90 days
            },
        ]

    def assess_control(
        self,
        control: dict[str, Any],
        evidence: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Evaluate compliance status of a control given evidence."""
        control_id = control.get("control_id", "")
        status = control.get("status", "not_applicable")
        gaps = list(control.get("gaps", []))

        evidence_refs = [e.get("id", "") for e in evidence if e.get("id")]

        # If we have no evidence for a non-compliant control, flag it
        if not evidence and status != "compliant":
            gaps.append(f"No evidence collected for {control_id}")
            if status != "non_compliant":
                status = "non_compliant"

        return {
            "control_id": control_id,
            "framework": control.get("framework", ""),
            "description": control.get("description", ""),
            "status": status,
            "evidence_refs": evidence_refs,
            "gaps": gaps,
        }

    def generate_audit_report(
        self,
        assessments: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Produce an audit-ready compliance report from control assessments."""
        total = len(assessments)
        if total == 0:
            return {
                "total_controls": 0,
                "compliant": 0,
                "non_compliant": 0,
                "partial": 0,
                "not_applicable": 0,
                "compliance_score": 0.0,
                "frameworks": [],
                "gaps": [],
                "recommendations": ["No controls assessed — scan required"],
                "generated_at": time.time(),
            }

        compliant = sum(1 for a in assessments if a.get("status") == "compliant")
        non_compliant = sum(1 for a in assessments if a.get("status") == "non_compliant")
        partial = sum(1 for a in assessments if a.get("status") == "partial")
        not_applicable = sum(1 for a in assessments if a.get("status") == "not_applicable")

        applicable = total - not_applicable
        score = round((compliant + partial * 0.5) / applicable, 4) if applicable > 0 else 0.0

        all_gaps: list[str] = []
        for a in assessments:
            for gap in a.get("gaps", []):
                all_gaps.append(f"{a.get('control_id', '')}: {gap}")

        frameworks = sorted({a.get("framework", "") for a in assessments if a.get("framework")})

        recommendations: list[str] = []
        if non_compliant > 0:
            recommendations.append(f"Remediate {non_compliant} non-compliant controls immediately")
        if partial > 0:
            recommendations.append(
                f"Complete implementation for {partial} partially compliant controls"
            )
        if not recommendations:
            recommendations.append("All assessed controls are compliant")

        return {
            "total_controls": total,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "partial": partial,
            "not_applicable": not_applicable,
            "compliance_score": score,
            "frameworks": frameworks,
            "gaps": all_gaps,
            "recommendations": recommendations,
            "generated_at": time.time(),
        }
