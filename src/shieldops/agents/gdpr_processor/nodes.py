"""GDPR Processor Agent — Node function implementations."""

from __future__ import annotations

from typing import Any

import structlog
from pydantic import BaseModel, Field

from shieldops.utils.llm import llm_structured

from .models import GDPRStage
from .tools import GDPRProcessorToolkit

logger = structlog.get_logger()

_toolkit: GDPRProcessorToolkit | None = None


def _get_toolkit() -> GDPRProcessorToolkit:
    global _toolkit
    if _toolkit is None:
        _toolkit = GDPRProcessorToolkit()
    return _toolkit


class _LLMDSARAnalysis(BaseModel):
    """LLM-generated DSAR processing analysis."""

    priority_requests: list[str] = Field(
        description="Request IDs requiring urgent attention",
    )
    sla_risk: str = Field(
        description="Overall SLA risk assessment",
    )
    recommendations: list[str] = Field(
        description="Recommendations for DSAR handling",
    )


async def intake_requests(
    state: dict[str, Any],
    toolkit: GDPRProcessorToolkit,
) -> dict[str, Any]:
    """Intake and validate pending DSARs."""
    logger.info("gdpr_processor.node.intake_requests")
    tenant_id = state.get("tenant_id", "")
    requests = await toolkit.intake_requests(tenant_id)

    return {
        "stage": GDPRStage.DATA_MAPPING.value,
        "dsar_requests": requests,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Ingested {len(requests)} DSARs for processing"],
    }


async def map_data(
    state: dict[str, Any],
    toolkit: GDPRProcessorToolkit,
) -> dict[str, Any]:
    """Map personal data across organizational systems."""
    logger.info("gdpr_processor.node.map_data")
    tenant_id = state.get("tenant_id", "")
    data_map = await toolkit.map_data_sources(tenant_id)

    return {
        "stage": GDPRStage.CONSENT_CHECK.value,
        "data_map": data_map,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Mapped {len(data_map)} data sources"],
    }


async def check_consent(
    state: dict[str, Any],
    toolkit: GDPRProcessorToolkit,
) -> dict[str, Any]:
    """Audit consent records for each data subject."""
    logger.info("gdpr_processor.node.check_consent")
    requests = state.get("dsar_requests", [])
    all_consents: list[dict[str, Any]] = []

    for req in requests:
        subject_id = req.get("subject_id", "")
        if subject_id:
            consents = await toolkit.check_consent(subject_id)
            all_consents.extend(consents)

    return {
        "stage": GDPRStage.PROCESS_REQUEST.value,
        "consent_records": all_consents,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Checked {len(all_consents)} consent records"],
    }


async def process_requests(
    state: dict[str, Any],
    toolkit: GDPRProcessorToolkit,
) -> dict[str, Any]:
    """Process DSARs with LLM-enhanced prioritization."""
    logger.info("gdpr_processor.node.process_requests")
    requests = state.get("dsar_requests", [])

    llm_text = ""
    try:
        summary = "\n".join(
            f"- {r.get('request_id', 'N/A')}: type={r.get('request_type')}, "
            f"subject={r.get('subject_id')}, deadline={r.get('response_deadline')}"
            for r in requests[:20]
        )
        analysis = await llm_structured(
            system_prompt=(
                "You are a GDPR compliance specialist. Analyze DSARs "
                "and prioritize by deadline urgency and request type."
            ),
            user_prompt=f"DSARs to process:\n{summary}",
            schema=_LLMDSARAnalysis,
        )
        if isinstance(analysis, _LLMDSARAnalysis):
            llm_text = (
                f"LLM SLA risk: {analysis.sla_risk}. "
                f"Priority: {len(analysis.priority_requests)} urgent."
            )
    except Exception:
        logger.debug("llm_fallback", agent="gdpr_processor", node="process")

    processed = len(requests)
    msg = f"Processed {processed} DSARs"
    if llm_text:
        msg += f" | {llm_text}"

    return {
        "stage": GDPRStage.BREACH_CHECK.value,
        "requests_processed": processed,
        "reasoning_chain": state.get("reasoning_chain", []) + [msg],
    }


async def check_breaches(
    state: dict[str, Any],
    toolkit: GDPRProcessorToolkit,
) -> dict[str, Any]:
    """Check for data breach notification obligations."""
    logger.info("gdpr_processor.node.check_breaches")
    tenant_id = state.get("tenant_id", "")
    breaches = await toolkit.check_breaches(tenant_id)

    return {
        "stage": GDPRStage.GENERATE_REPORT.value,
        "breach_records": breaches,
        "breaches_detected": len(breaches),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Detected {len(breaches)} breach incidents"],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: GDPRProcessorToolkit,
) -> dict[str, Any]:
    """Generate GDPR compliance report."""
    logger.info("gdpr_processor.node.generate_report")
    report = toolkit.generate_compliance_report(
        requests=state.get("dsar_requests", []),
        consents=state.get("consent_records", []),
        data_map=state.get("data_map", []),
        breaches=state.get("breach_records", []),
    )

    return {
        "stage": GDPRStage.GENERATE_REPORT.value,
        "report": report,
        "compliance_score": report.get("compliance_score", 0.0),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Report generated: score={report.get('compliance_score', 0)}, "
            f"{report.get('total_dsars', 0)} DSARs"
        ],
    }
