"""Vendor Compliance Assessor Agent — Tool functions."""

from __future__ import annotations

import time
from typing import Any

import structlog

from .models import ComplianceScore

logger = structlog.get_logger()

_MOCK_VENDORS: list[dict[str, Any]] = [
    {
        "name": "CloudAuth Inc",
        "tier": "critical",
        "category": "Identity Provider",
        "data_access": True,
    },
    {
        "name": "DataStore Pro",
        "tier": "high",
        "category": "Database SaaS",
        "data_access": True,
    },
    {
        "name": "MonitorCorp",
        "tier": "medium",
        "category": "Observability",
        "data_access": False,
    },
    {
        "name": "MailRelay",
        "tier": "low",
        "category": "Email Service",
        "data_access": False,
    },
    {
        "name": "OfficeTools",
        "tier": "minimal",
        "category": "Productivity",
        "data_access": False,
    },
]

_QUESTIONS = [
    "Do you encrypt data at rest and in transit?",
    "Do you have SOC 2 Type II certification?",
    "Do you conduct annual penetration testing?",
    "Do you have an incident response plan?",
    "Do you support MFA for all access?",
]


class VendorComplianceAssessorToolkit:
    """Tools for vendor compliance assessment."""

    def __init__(
        self,
        vendor_db: Any | None = None,
        questionnaire_api: Any | None = None,
        risk_engine: Any | None = None,
    ) -> None:
        self._vendor_db = vendor_db
        self._questionnaire_api = questionnaire_api
        self._risk_engine = risk_engine

    async def inventory_vendors(
        self,
        tenant_id: str,
    ) -> list[dict[str, Any]]:
        """Inventory all vendors."""
        logger.info(
            "vca.inventory",
            tenant_id=tenant_id,
        )

        if self._vendor_db is not None:
            try:
                return await self._vendor_db.list(
                    tenant_id=tenant_id,
                )
            except Exception:
                logger.exception("vca.inventory.error")

        results: list[dict[str, Any]] = []
        for i, v in enumerate(_MOCK_VENDORS):
            results.append(
                {
                    "id": f"vnd-{i:03d}",
                    "name": v["name"],
                    "tier": v["tier"],
                    "category": v["category"],
                    "data_access": v["data_access"],
                    "contract_expiry": "2027-01-01",
                    "last_assessed": "2025-12-01",
                }
            )
        return results

    async def collect_questionnaires(
        self,
        vendor: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Collect questionnaire responses from vendor."""
        logger.info(
            "vca.questionnaire",
            vendor=vendor.get("name"),
        )

        if self._questionnaire_api is not None:
            try:
                return await self._questionnaire_api.get(
                    vendor_id=vendor.get("id", ""),
                )
            except Exception:
                logger.exception("vca.questionnaire.err")

        vid = vendor.get("id", "")
        tier = vendor.get("tier", "medium")
        results: list[dict[str, Any]] = []
        for i, q in enumerate(_QUESTIONS):
            compliant = not (tier in ("minimal", "low") and i > 2)
            results.append(
                {
                    "vendor_id": vid,
                    "question_id": f"q-{i:02d}",
                    "question": q,
                    "answer": "Yes" if compliant else "No",
                    "compliant": compliant,
                }
            )
        return results

    def assess_risk(
        self,
        vendor: dict[str, Any],
        responses: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Assess vendor risk based on responses."""
        total = len(responses)
        compliant = sum(1 for r in responses if r.get("compliant"))
        ratio = compliant / max(total, 1)

        risk_factors: list[str] = []
        for r in responses:
            if not r.get("compliant"):
                risk_factors.append(f"Non-compliant: {r.get('question')}")

        if vendor.get("data_access"):
            risk_factors.append(
                "Vendor has access to sensitive data",
            )

        if ratio >= 0.9:
            score = ComplianceScore.EXCELLENT
        elif ratio >= 0.75:
            score = ComplianceScore.GOOD
        elif ratio >= 0.6:
            score = ComplianceScore.ACCEPTABLE
        elif ratio >= 0.4:
            score = ComplianceScore.POOR
        else:
            score = ComplianceScore.FAILING

        return {
            "vendor_id": vendor.get("id", ""),
            "vendor_name": vendor.get("name", ""),
            "tier": vendor.get("tier", "medium"),
            "score": score.value,
            "risk_factors": risk_factors,
            "score_value": round(ratio * 100, 1),
        }

    def generate_report(
        self,
        vendors: list[dict[str, Any]],
        assessments: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Generate vendor compliance report."""
        critical = sum(1 for v in vendors if v.get("tier") == "critical")
        failing = sum(1 for a in assessments if a.get("score") == "failing")
        poor = sum(1 for a in assessments if a.get("score") == "poor")
        avg_score = sum(a.get("score_value", 0) for a in assessments) / max(len(assessments), 1)

        return {
            "total_vendors": len(vendors),
            "critical_vendors": critical,
            "failing_vendors": failing,
            "poor_vendors": poor,
            "average_score": round(avg_score, 1),
            "assessments": assessments,
            "generated_at": time.time(),
        }
