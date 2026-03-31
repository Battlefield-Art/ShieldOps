"""Node implementations for the Email Authentication
Auditor Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.email_authentication_auditor.models import (
    EmailAuthenticationAuditorState,
    EmailAuthStage,
)
from shieldops.agents.email_authentication_auditor.prompts import (
    SYSTEM_DMARC_CHECK,
    SYSTEM_DOMAIN_SCAN,
    SYSTEM_REPORT,
    SYSTEM_SPF_CHECK,
    DMARCAnalysisOutput,
    DomainScanOutput,
    EmailAuthReportOutput,
    SPFAnalysisOutput,
)
from shieldops.agents.email_authentication_auditor.tools import (
    EmailAuthenticationAuditorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: EmailAuthenticationAuditorToolkit | None = None


def set_toolkit(
    toolkit: EmailAuthenticationAuditorToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> EmailAuthenticationAuditorToolkit:
    if _toolkit is None:
        return EmailAuthenticationAuditorToolkit()
    return _toolkit


# ------------------------------------------------------------------
# Node: scan_domains
# ------------------------------------------------------------------


async def scan_domains(
    state: EmailAuthenticationAuditorState,
) -> dict[str, Any]:
    """Scan organizational domains for email auth."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    domains = await toolkit.scan_domains(
        tenant_id=state.tenant_id,
    )

    try:
        ctx = _json.dumps(
            {"tenant_id": state.tenant_id, "domains": domains[:5]},
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_DOMAIN_SCAN,
            user_prompt=f"Scan domains:\n{ctx}",
            schema=DomainScanOutput,
        )
        if llm_out.domains:  # type: ignore[union-attr]
            domains = [*domains, *llm_out.domains]  # type: ignore[union-attr]
        logger.info(
            "llm_enhanced",
            node="scan_domains",
            count=len(llm_out.domains),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="scan_domains")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "domains": domains,
        "total_domains": len(domains),
        "stage": EmailAuthStage.SCAN_DOMAINS,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Scanned {len(domains)} domains ({elapsed}ms)",
        ],
        "current_step": "scan_domains",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: check_spf
# ------------------------------------------------------------------


async def check_spf(
    state: EmailAuthenticationAuditorState,
) -> dict[str, Any]:
    """Check SPF records for all domains."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.check_spf(domains=state.domains)

    try:
        ctx = _json.dumps(
            {"spf_results": results[:5]},
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_SPF_CHECK,
            user_prompt=f"Analyze SPF:\n{ctx}",
            schema=SPFAnalysisOutput,
        )
        logger.info(
            "llm_enhanced",
            node="check_spf",
            valid=llm_out.valid_count,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="check_spf")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "spf_results": results,
        "stage": EmailAuthStage.CHECK_SPF,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Checked SPF for {len(results)} domains ({elapsed}ms)",
        ],
        "current_step": "check_spf",
    }


# ------------------------------------------------------------------
# Node: check_dkim
# ------------------------------------------------------------------


async def check_dkim(
    state: EmailAuthenticationAuditorState,
) -> dict[str, Any]:
    """Check DKIM records for all domains."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.check_dkim(domains=state.domains)

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "dkim_results": results,
        "stage": EmailAuthStage.CHECK_DKIM,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Checked DKIM for {len(results)} domains ({elapsed}ms)",
        ],
        "current_step": "check_dkim",
    }


# ------------------------------------------------------------------
# Node: check_dmarc
# ------------------------------------------------------------------


async def check_dmarc(
    state: EmailAuthenticationAuditorState,
) -> dict[str, Any]:
    """Check DMARC records for all domains."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.check_dmarc(domains=state.domains)

    try:
        ctx = _json.dumps(
            {"dmarc_results": results[:5]},
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_DMARC_CHECK,
            user_prompt=f"Analyze DMARC:\n{ctx}",
            schema=DMARCAnalysisOutput,
        )
        logger.info(
            "llm_enhanced",
            node="check_dmarc",
            reject=llm_out.reject_count,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="check_dmarc")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "dmarc_results": results,
        "stage": EmailAuthStage.CHECK_DMARC,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Checked DMARC for {len(results)} domains ({elapsed}ms)",
        ],
        "current_step": "check_dmarc",
    }


# ------------------------------------------------------------------
# Node: assess_posture
# ------------------------------------------------------------------


async def assess_posture(
    state: EmailAuthenticationAuditorState,
) -> dict[str, Any]:
    """Assess overall email authentication posture."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    posture = await toolkit.assess_email_posture(
        spf=state.spf_results,
        dkim=state.dkim_results,
        dmarc=state.dmarc_results,
    )

    compliant = sum(
        1 for d in state.dmarc_results if d.get("status") == "pass" and d.get("policy") == "reject"
    )
    total = max(state.total_domains, 1)
    compliance_pct = round((compliant / total) * 100, 1)

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "posture_assessment": posture,
        "domains_compliant": compliant,
        "compliance_pct": compliance_pct,
        "stage": EmailAuthStage.ASSESS_POSTURE,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Posture: {compliant}/{total} compliant, {compliance_pct}% ({elapsed}ms)",
        ],
        "current_step": "assess_posture",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: EmailAuthenticationAuditorState,
) -> dict[str, Any]:
    """Generate email authentication audit report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {
        "total_domains": state.total_domains,
        "domains_compliant": state.domains_compliant,
        "compliance_pct": state.compliance_pct,
    }

    try:
        ctx = _json.dumps(
            {
                "total_domains": state.total_domains,
                "compliance_pct": state.compliance_pct,
                "spf": state.spf_results[:5],
                "dkim": state.dkim_results[:5],
                "dmarc": state.dmarc_results[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate email auth report:\n{ctx}",
            schema=EmailAuthReportOutput,
        )
        if isinstance(llm_out, EmailAuthReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "critical_gaps": llm_out.critical_gaps,
                    "recommendations": llm_out.recommendations,
                    "risk_level": llm_out.risk_level,
                }
            )
        logger.info("llm_enhanced", node="generate_report")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="generate_report")

    await toolkit.record_metric(
        "compliance_pct",
        state.compliance_pct,
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    return {
        "stats": report,
        "stage": EmailAuthStage.REPORT,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Report generated ({elapsed}ms)",
        ],
        "current_step": "complete",
    }
