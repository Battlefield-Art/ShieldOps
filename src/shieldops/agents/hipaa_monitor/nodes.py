"""HIPAA Monitor Agent — Node function implementations."""

from __future__ import annotations

from typing import Any

import structlog
from pydantic import BaseModel, Field

from shieldops.utils.llm import llm_structured

from .models import HIPAAStage
from .tools import HIPAAMonitorToolkit

logger = structlog.get_logger()

_toolkit: HIPAAMonitorToolkit | None = None


def _get_toolkit() -> HIPAAMonitorToolkit:
    global _toolkit
    if _toolkit is None:
        _toolkit = HIPAAMonitorToolkit()
    return _toolkit


class _LLMPHIAnalysis(BaseModel):
    """LLM-generated PHI access analysis."""

    suspicious_patterns: list[str] = Field(
        description="Suspicious PHI access patterns detected",
    )
    risk_level: str = Field(
        description="Overall risk level (low/medium/high/critical)",
    )
    recommendations: list[str] = Field(
        description="Recommendations for PHI access governance",
    )


async def audit_access(
    state: dict[str, Any],
    toolkit: HIPAAMonitorToolkit,
) -> dict[str, Any]:
    """Audit PHI access logs for compliance."""
    logger.info("hipaa_monitor.node.audit_access")
    tenant_id = state.get("tenant_id", "")
    access_logs = await toolkit.audit_phi_access(tenant_id)

    return {
        "stage": HIPAAStage.MINIMUM_NECESSARY.value,
        "access_logs": access_logs,
        "phi_accesses_audited": len(access_logs),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Audited {len(access_logs)} PHI access events"],
    }


async def check_minimum_necessary(
    state: dict[str, Any],
    toolkit: HIPAAMonitorToolkit,
) -> dict[str, Any]:
    """Enforce minimum necessary standard."""
    logger.info("hipaa_monitor.node.minimum_necessary")
    access_logs = state.get("access_logs", [])
    violations = await toolkit.check_minimum_necessary(access_logs)

    return {
        "stage": HIPAAStage.BAA_CHECK.value,
        "minimum_necessary_violations": violations,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Found {len(violations)} minimum necessary violations"],
    }


async def check_baas(
    state: dict[str, Any],
    toolkit: HIPAAMonitorToolkit,
) -> dict[str, Any]:
    """Check BAA tracking status."""
    logger.info("hipaa_monitor.node.check_baas")
    tenant_id = state.get("tenant_id", "")
    baas = await toolkit.check_baas(tenant_id)

    expired = [b for b in baas if b.get("status") == "expired"]

    return {
        "stage": HIPAAStage.SECURITY_RULE.value,
        "baa_records": baas,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Checked {len(baas)} BAAs, {len(expired)} expired"],
    }


async def assess_security_rule(
    state: dict[str, Any],
    toolkit: HIPAAMonitorToolkit,
) -> dict[str, Any]:
    """Assess HIPAA Security Rule controls with LLM enhancement."""
    logger.info("hipaa_monitor.node.security_rule")
    tenant_id = state.get("tenant_id", "")
    controls = await toolkit.assess_security_controls(tenant_id)
    access_logs = state.get("access_logs", [])

    llm_text = ""
    try:
        log_summary = "\n".join(
            f"- {lg.get('log_id')}: user={lg.get('user_id')}, "
            f"phi={lg.get('phi_category')}, justified={lg.get('justified')}"
            for lg in access_logs[:20]
        )
        analysis = await llm_structured(
            system_prompt=(
                "You are a HIPAA compliance analyst. Review PHI access "
                "patterns and identify potential violations."
            ),
            user_prompt=(f"PHI access logs:\n{log_summary}\n\nControls assessed: {len(controls)}"),
            schema=_LLMPHIAnalysis,
        )
        if isinstance(analysis, _LLMPHIAnalysis):
            llm_text = (
                f"LLM risk: {analysis.risk_level}. "
                f"Suspicious patterns: {len(analysis.suspicious_patterns)}."
            )
    except Exception:
        logger.debug("llm_fallback", agent="hipaa_monitor", node="security")

    violations = state.get("minimum_necessary_violations", [])
    msg = f"Assessed {len(controls)} Security Rule controls"
    if llm_text:
        msg += f" | {llm_text}"

    return {
        "stage": HIPAAStage.GENERATE_REPORT.value,
        "security_controls": controls,
        "violations_found": len(violations),
        "reasoning_chain": state.get("reasoning_chain", []) + [msg],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: HIPAAMonitorToolkit,
) -> dict[str, Any]:
    """Generate HIPAA compliance report."""
    logger.info("hipaa_monitor.node.generate_report")
    report = toolkit.generate_hipaa_report(
        access_logs=state.get("access_logs", []),
        violations=state.get("minimum_necessary_violations", []),
        baas=state.get("baa_records", []),
        controls=state.get("security_controls", []),
    )

    return {
        "stage": HIPAAStage.GENERATE_REPORT.value,
        "report": report,
        "compliance_score": report.get("compliance_score", 0.0),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Report generated: score={report.get('compliance_score', 0)}, "
            f"{report.get('violations_found', 0)} violations"
        ],
    }
