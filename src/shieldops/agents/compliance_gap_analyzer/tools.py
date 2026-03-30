"""Compliance Gap Analyzer Agent — Tool functions."""

from __future__ import annotations

import time
from typing import Any

import structlog

logger = structlog.get_logger()

_DOMAIN_FRAMEWORKS: dict[str, list[str]] = {
    "financial": ["SOC2", "PCI-DSS", "SOX", "GLBA"],
    "healthcare": ["HIPAA", "HITRUST", "SOC2"],
    "government": ["FedRAMP", "NIST-800-53", "FISMA"],
    "technology": ["SOC2", "ISO-27001", "GDPR"],
    "retail": ["PCI-DSS", "SOC2", "CCPA"],
    "energy": ["NERC-CIP", "NIST-CSF", "SOC2"],
}

_FRAMEWORK_REQUIREMENTS: dict[str, list[dict[str, Any]]] = {
    "SOC2": [
        {
            "requirement_id": "SOC2-CC6.1",
            "title": "Logical access controls",
            "description": ("Restrict logical access to systems"),
            "mandatory": True,
        },
        {
            "requirement_id": "SOC2-CC6.3",
            "title": "Role-based access",
            "description": ("Implement role-based access control"),
            "mandatory": True,
        },
        {
            "requirement_id": "SOC2-CC7.2",
            "title": "Monitoring and detection",
            "description": ("Monitor system components for anomalies"),
            "mandatory": True,
        },
        {
            "requirement_id": "SOC2-CC8.1",
            "title": "Change management",
            "description": ("Authorize and test changes before deploy"),
            "mandatory": True,
        },
    ],
    "PCI-DSS": [
        {
            "requirement_id": "PCI-1.1",
            "title": "Network segmentation",
            "description": ("Install network security controls"),
            "mandatory": True,
        },
        {
            "requirement_id": "PCI-3.4",
            "title": "Encryption at rest",
            "description": ("Render PAN unreadable when stored"),
            "mandatory": True,
        },
        {
            "requirement_id": "PCI-6.2",
            "title": "Secure development",
            "description": "Develop software securely",
            "mandatory": True,
        },
        {
            "requirement_id": "PCI-10.1",
            "title": "Audit logging",
            "description": ("Log and monitor all access to systems"),
            "mandatory": True,
        },
    ],
    "HIPAA": [
        {
            "requirement_id": "HIPAA-164.312a",
            "title": "Access control",
            "description": "Unique user identification",
            "mandatory": True,
        },
        {
            "requirement_id": "HIPAA-164.312b",
            "title": "Audit controls",
            "description": ("Record and examine system activity"),
            "mandatory": True,
        },
        {
            "requirement_id": "HIPAA-164.312e",
            "title": "Transmission security",
            "description": "Encrypt ePHI in transit",
            "mandatory": True,
        },
    ],
    "ISO-27001": [
        {
            "requirement_id": "ISO-A5.1",
            "title": "Information security policies",
            "description": ("Management direction for info security"),
            "mandatory": True,
        },
        {
            "requirement_id": "ISO-A9.1",
            "title": "Access control policy",
            "description": ("Limit access to information assets"),
            "mandatory": True,
        },
        {
            "requirement_id": "ISO-A12.4",
            "title": "Logging and monitoring",
            "description": ("Record events and generate evidence"),
            "mandatory": True,
        },
    ],
    "GDPR": [
        {
            "requirement_id": "GDPR-Art25",
            "title": "Data protection by design",
            "description": "Privacy by design and default",
            "mandatory": True,
        },
        {
            "requirement_id": "GDPR-Art32",
            "title": "Security of processing",
            "description": ("Appropriate technical measures"),
            "mandatory": True,
        },
        {
            "requirement_id": "GDPR-Art33",
            "title": "Breach notification",
            "description": ("Notify authority within 72 hours"),
            "mandatory": True,
        },
    ],
}

_POSTURE_CONTROLS: list[dict[str, Any]] = [
    {
        "control": "mfa_enforcement",
        "status": "implemented",
        "effectiveness": 0.95,
    },
    {
        "control": "encryption_at_rest",
        "status": "implemented",
        "effectiveness": 0.90,
    },
    {
        "control": "encryption_in_transit",
        "status": "implemented",
        "effectiveness": 0.92,
    },
    {
        "control": "audit_logging",
        "status": "partial",
        "effectiveness": 0.60,
    },
    {
        "control": "network_segmentation",
        "status": "partial",
        "effectiveness": 0.55,
    },
    {
        "control": "change_management",
        "status": "implemented",
        "effectiveness": 0.85,
    },
    {
        "control": "vulnerability_scanning",
        "status": "missing",
        "effectiveness": 0.0,
    },
    {
        "control": "incident_response",
        "status": "partial",
        "effectiveness": 0.45,
    },
    {
        "control": "data_classification",
        "status": "missing",
        "effectiveness": 0.0,
    },
    {
        "control": "access_reviews",
        "status": "partial",
        "effectiveness": 0.50,
    },
]


class ComplianceGapAnalyzerToolkit:
    """Tools for compliance gap analysis and planning."""

    def __init__(
        self,
        posture_backend: Any | None = None,
        regulatory_backend: Any | None = None,
    ) -> None:
        self._posture_backend = posture_backend
        self._regulatory_backend = regulatory_backend

    async def scan_posture(
        self,
        domain: str,
    ) -> dict[str, Any]:
        """Scan current security posture for a domain."""
        logger.info(
            "cga.scan_posture",
            domain=domain,
        )
        if self._posture_backend is not None:
            try:
                posture_result: dict[str, Any] = await self._posture_backend.scan(
                    domain=domain,
                )
                return posture_result
            except Exception:
                logger.exception(
                    "cga.scan_posture.error",
                )
                return {}

        controls = _POSTURE_CONTROLS
        implemented = sum(1 for c in controls if c["status"] == "implemented")
        partial = sum(1 for c in controls if c["status"] == "partial")
        missing = sum(1 for c in controls if c["status"] == "missing")
        total = len(controls)
        score = (
            round(
                (implemented + partial * 0.5) / total * 100,
                2,
            )
            if total > 0
            else 0.0
        )

        return {
            "scan_id": (f"scan-{domain}-{int(time.time())}"),
            "domain": domain,
            "controls_total": total,
            "controls_implemented": implemented,
            "controls_partial": partial,
            "controls_missing": missing,
            "score": score,
            "findings": controls,
        }

    async def fetch_requirements(
        self,
        domain: str,
    ) -> list[dict[str, Any]]:
        """Fetch regulatory requirements for a domain."""
        logger.info(
            "cga.fetch_requirements",
            domain=domain,
        )
        if self._regulatory_backend is not None:
            try:
                requirements: list[dict[str, Any]] = await self._regulatory_backend.fetch(
                    domain=domain,
                )
                return requirements
            except Exception:
                logger.exception(
                    "cga.fetch_requirements.error",
                )
                return []

        frameworks = _DOMAIN_FRAMEWORKS.get(
            domain,
            [],
        )
        results: list[dict[str, Any]] = []
        for fw in frameworks:
            reqs = _FRAMEWORK_REQUIREMENTS.get(
                fw,
                [],
            )
            for req in reqs:
                results.append(
                    {
                        **req,
                        "framework": fw,
                        "domain": domain,
                        "control_mappings": [],
                    }
                )
        return results

    def identify_gaps(
        self,
        posture: dict[str, Any],
        requirements: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Compare posture against requirements."""
        findings = posture.get("findings", [])
        implemented = {f["control"] for f in findings if f.get("status") == "implemented"}
        partial = {f["control"] for f in findings if f.get("status") == "partial"}

        gaps: list[dict[str, Any]] = []
        for i, req in enumerate(requirements):
            req_id = req.get("requirement_id", "")
            title = req.get("title", "")

            ctrl_key = title.lower().replace(" ", "_")
            has_full = any(ctrl_key in c for c in implemented)
            has_partial = any(ctrl_key in c for c in partial)

            if has_full:
                continue

            if has_partial:
                severity = "medium"
                current = "partially implemented"
            else:
                severity = "high"
                current = "not implemented"

            if req.get("mandatory", True) and severity == "high":
                severity = "critical"

            gaps.append(
                {
                    "gap_id": f"GAP-{i + 1:04d}",
                    "requirement_id": req_id,
                    "framework": req.get(
                        "framework",
                        "",
                    ),
                    "severity": severity,
                    "description": (f"Gap in {title}: {current}"),
                    "current_state": current,
                    "required_state": req.get(
                        "description",
                        "",
                    ),
                    "affected_controls": [],
                }
            )
        return gaps

    def prioritize_risks(
        self,
        gaps: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Score and prioritize gaps by risk."""
        severity_scores = {
            "critical": 90.0,
            "high": 70.0,
            "medium": 45.0,
            "low": 20.0,
            "informational": 5.0,
        }
        penalties = {
            "critical": ("Regulatory action / fines"),
            "high": ("Audit finding / remediation order"),
            "medium": ("Observation / conditional pass"),
            "low": "Advisory note",
            "informational": ("Best practice suggestion"),
        }

        priorities: list[dict[str, Any]] = []
        for gap in gaps:
            sev = gap.get("severity", "medium")
            base = severity_scores.get(sev, 45.0)
            fw = gap.get("framework", "")
            fw_boost = (
                5.0
                if fw
                in (
                    "PCI-DSS",
                    "HIPAA",
                    "FedRAMP",
                )
                else 0.0
            )
            score = min(base + fw_boost, 100.0)

            priorities.append(
                {
                    "gap_id": gap.get("gap_id", ""),
                    "severity": sev,
                    "risk_score": score,
                    "business_impact": (f"{sev.title()} impact on compliance posture"),
                    "regulatory_penalty": (penalties.get(sev, "")),
                    "likelihood": round(
                        score / 100.0,
                        2,
                    ),
                }
            )

        priorities.sort(
            key=lambda p: p["risk_score"],
            reverse=True,
        )
        return priorities

    def build_remediation_plan(
        self,
        gaps: list[dict[str, Any]],
        priorities: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Generate remediation plans for gaps."""
        plans: list[dict[str, Any]] = []

        for rank, gap in enumerate(gaps, 1):
            gap_id = gap.get("gap_id", "")
            sev = gap.get("severity", "medium")

            effort = {
                "critical": 14,
                "high": 10,
                "medium": 5,
                "low": 2,
                "informational": 1,
            }.get(sev, 5)

            plans.append(
                {
                    "gap_id": gap_id,
                    "title": (f"Remediate {gap.get('description', '')}"),
                    "steps": [
                        "Assess current control state",
                        "Design remediation approach",
                        "Implement control changes",
                        "Validate compliance",
                        "Document evidence",
                    ],
                    "estimated_effort_days": effort,
                    "owner": "security-team",
                    "priority_rank": rank,
                    "dependencies": [],
                }
            )

        plans.sort(
            key=lambda p: p["priority_rank"],
        )
        return plans

    def generate_report(
        self,
        posture_scans: list[dict[str, Any]],
        gaps: list[dict[str, Any]],
        priorities: list[dict[str, Any]],
        plans: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Produce final compliance gap report."""
        total_gaps = len(gaps)
        critical = sum(1 for g in gaps if g.get("severity") == "critical")
        high = sum(1 for g in gaps if g.get("severity") == "high")
        medium = sum(1 for g in gaps if g.get("severity") == "medium")

        avg_score = 0.0
        if posture_scans:
            scores = [s.get("score", 0.0) for s in posture_scans]
            avg_score = round(
                sum(scores) / len(scores),
                2,
            )

        total_effort = sum(p.get("estimated_effort_days", 0) for p in plans)

        frameworks = sorted({g.get("framework", "") for g in gaps})

        low_count = total_gaps - critical - high - medium

        return {
            "compliance_score": avg_score,
            "total_gaps": total_gaps,
            "gaps_by_severity": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low_count,
            },
            "frameworks_assessed": frameworks,
            "remediation_plans": len(plans),
            "total_effort_days": total_effort,
            "top_risks": list(priorities[:5]),
            "generated_at": time.time(),
        }
