"""Vendor Compliance Assessor Agent — Node implementations."""

from __future__ import annotations

from typing import Any

import structlog
from pydantic import BaseModel, Field

from shieldops.utils.llm import llm_structured

from .models import VCAStage
from .tools import VendorComplianceAssessorToolkit

logger = structlog.get_logger()

_toolkit: VendorComplianceAssessorToolkit | None = None


def _get_toolkit() -> VendorComplianceAssessorToolkit:
    if _toolkit is None:
        return VendorComplianceAssessorToolkit()
    return _toolkit


class _LLMRiskInsight(BaseModel):
    """LLM-generated vendor risk insight."""

    high_risk_vendors: list[str] = Field(
        description="Vendors requiring immediate action",
    )
    risk_patterns: list[str] = Field(
        description="Common compliance gaps observed",
    )
    recommendation: str = Field(
        description="Overall vendor risk posture summary",
    )


async def inventory_vendors(
    state: dict[str, Any],
    toolkit: VendorComplianceAssessorToolkit,
) -> dict[str, Any]:
    """Inventory all vendors."""
    logger.info("vca.node.inventory_vendors")

    tenant_id = state.get("tenant_id", "default")
    vendors = await toolkit.inventory_vendors(tenant_id)

    critical = sum(1 for v in vendors if v.get("tier") == "critical")

    return {
        "stage": VCAStage.COLLECT_QUESTIONNAIRES.value,
        "vendors": vendors,
        "total_vendors": len(vendors),
        "critical_vendors": critical,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [f"Inventoried {len(vendors)} vendors, {critical} critical"],
    }


async def collect_questionnaires(
    state: dict[str, Any],
    toolkit: VendorComplianceAssessorToolkit,
) -> dict[str, Any]:
    """Collect questionnaire responses."""
    logger.info("vca.node.collect_questionnaires")
    vendors = state.get("vendors", [])

    all_responses: list[dict[str, Any]] = []
    for vendor in vendors:
        responses = await toolkit.collect_questionnaires(
            vendor,
        )
        all_responses.extend(responses)

    return {
        "stage": VCAStage.ASSESS_RISK.value,
        "questionnaires": all_responses,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [f"Collected {len(all_responses)} responses from {len(vendors)} vendors"],
    }


async def assess_risk(
    state: dict[str, Any],
    toolkit: VendorComplianceAssessorToolkit,
) -> dict[str, Any]:
    """Assess risk for each vendor."""
    logger.info("vca.node.assess_risk")
    vendors = state.get("vendors", [])
    questionnaires = state.get("questionnaires", [])

    # Group responses by vendor
    by_vendor: dict[str, list[dict[str, Any]]] = {}
    for q in questionnaires:
        vid = q.get("vendor_id", "")
        by_vendor.setdefault(vid, []).append(q)

    assessments: list[dict[str, Any]] = []
    for vendor in vendors:
        vid = vendor.get("id", "")
        responses = by_vendor.get(vid, [])
        assessment = toolkit.assess_risk(
            vendor,
            responses,
        )
        assessments.append(assessment)

    return {
        "stage": VCAStage.SCORE_COMPLIANCE.value,
        "assessments": assessments,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [f"Assessed risk for {len(assessments)} vendors"],
    }


async def score_compliance(
    state: dict[str, Any],
    toolkit: VendorComplianceAssessorToolkit,
) -> dict[str, Any]:
    """Score and classify vendor compliance."""
    logger.info("vca.node.score_compliance")
    assessments = state.get("assessments", [])

    failing = sum(1 for a in assessments if a.get("score") == "failing")

    llm_note = ""
    try:
        summary = "\n".join(
            f"- {a.get('vendor_name')}: {a.get('score')} ({a.get('score_value')})"
            for a in assessments[:20]
        )
        result = await llm_structured(
            system_prompt=(
                "You are a vendor risk analyst. "
                "Analyze vendor compliance scores and "
                "identify systemic risk patterns."
            ),
            user_prompt=f"Vendor scores:\n{summary}",
            schema=_LLMRiskInsight,
        )
        if isinstance(result, _LLMRiskInsight):
            llm_note = f" LLM: {result.recommendation}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="vca",
            node="score",
        )

    note = f"Scored {len(assessments)} vendors, {failing} failing"
    return {
        "stage": VCAStage.GENERATE_REPORT.value,
        "failing_vendors": failing,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [note + llm_note],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: VendorComplianceAssessorToolkit,
) -> dict[str, Any]:
    """Generate vendor compliance report."""
    logger.info("vca.node.generate_report")

    rpt = toolkit.generate_report(
        vendors=state.get("vendors", []),
        assessments=state.get("assessments", []),
    )

    return {
        "stage": VCAStage.REPORT.value,
        "report": rpt,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [f"Report: {rpt.get('total_vendors')} vendors, avg score {rpt.get('average_score')}"],
    }


async def report(
    state: dict[str, Any],
    toolkit: VendorComplianceAssessorToolkit,
) -> dict[str, Any]:
    """Finalize the vendor compliance assessment."""
    logger.info("vca.node.report")
    return {
        "stage": VCAStage.REPORT.value,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + ["Assessment complete"],
    }
