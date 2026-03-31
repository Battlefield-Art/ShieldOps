"""Node implementations for the Wireless Security Auditor
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.wireless_security_auditor.models import (
    ReasoningStep,
    WirelessSecurityAuditorState,
    WSAStage,
)
from shieldops.agents.wireless_security_auditor.prompts import (
    SYSTEM_ENCRYPTION_AUDIT,
    SYSTEM_REPORT,
    SYSTEM_RISK_ASSESSMENT,
    SYSTEM_ROGUE_DETECTION,
    EncryptionAuditOutput,
    RogueDetectionOutput,
    WirelessReportOutput,
    WirelessRiskOutput,
)
from shieldops.agents.wireless_security_auditor.tools import (
    WirelessSecurityToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: WirelessSecurityToolkit | None = None


def set_toolkit(
    toolkit: WirelessSecurityToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> WirelessSecurityToolkit:
    if _toolkit is None:
        return WirelessSecurityToolkit()
    return _toolkit


def _step(
    chain: list[ReasoningStep],
    action: str,
    input_summary: str,
    output_summary: str,
    start: datetime,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Build a reasoning step with duration."""
    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return ReasoningStep(
        step_number=len(chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=elapsed,
        tool_used=tool_used,
    )


# ------------------------------------------------------------------
# Node: discover_networks
# ------------------------------------------------------------------


async def discover_networks(
    state: WirelessSecurityAuditorState,
) -> dict[str, Any]:
    """Discover wireless networks at the target site."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    networks = await toolkit.discover_networks(
        scope=state.scan_scope,
        site_name=state.site_name,
    )

    step = _step(
        state.reasoning_chain,
        "discover_networks",
        f"Site: {state.site_name}",
        f"Discovered {len(networks)} networks",
        start,
        "network_scanner",
    )

    return {
        "networks": networks,
        "total_networks": len(networks),
        "stage": WSAStage.DISCOVER_NETWORKS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "discover_networks",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: scan_access_points
# ------------------------------------------------------------------


async def scan_access_points(
    state: WirelessSecurityAuditorState,
) -> dict[str, Any]:
    """Scan access points for detailed configuration."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    aps = await toolkit.scan_access_points(
        networks=state.networks,
    )

    step = _step(
        state.reasoning_chain,
        "scan_access_points",
        (f"Scanning APs from {len(state.networks)} networks"),
        f"Found {len(aps)} access points",
        start,
        "ap_inventory",
    )

    return {
        "access_points": aps,
        "total_access_points": len(aps),
        "stage": WSAStage.SCAN_ACCESS_POINTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "scan_access_points",
    }


# ------------------------------------------------------------------
# Node: check_encryption
# ------------------------------------------------------------------


async def check_encryption(
    state: WirelessSecurityAuditorState,
) -> dict[str, Any]:
    """Audit encryption on all access points."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    findings = await toolkit.check_encryption(
        access_points=state.access_points,
        compliance_standard=state.compliance_standard,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "ap_count": len(state.access_points),
                "aps_sample": state.access_points[:5],
                "standard": state.compliance_standard,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ENCRYPTION_AUDIT,
            user_prompt=(f"Audit encryption:\n{ctx}"),
            schema=EncryptionAuditOutput,
        )
        if llm_out.weaknesses:  # type: ignore[union-attr]
            findings.append(
                {
                    "finding_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "non_compliant": llm_out.non_compliant_count,  # type: ignore[union-attr]
                    "weaknesses": llm_out.weaknesses,  # type: ignore[union-attr]
                    "upgrades": llm_out.upgrade_recommendations,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="check_encryption",
            weaknesses=len(llm_out.weaknesses),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="check_encryption",
        )

    non_compliant = sum(1 for f in findings if not f.get("is_compliant", True))

    step = _step(
        state.reasoning_chain,
        "check_encryption",
        (f"Auditing {len(state.access_points)} APs against {state.compliance_standard}"),
        (f"{len(findings)} findings, {non_compliant} non-compliant"),
        start,
        "encryption_checker",
    )

    return {
        "encryption_findings": findings,
        "non_compliant_count": non_compliant,
        "stage": WSAStage.CHECK_ENCRYPTION,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "check_encryption",
    }


# ------------------------------------------------------------------
# Node: detect_rogues
# ------------------------------------------------------------------


async def detect_rogues(
    state: WirelessSecurityAuditorState,
) -> dict[str, Any]:
    """Detect rogue and evil twin access points."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    rogues = await toolkit.detect_rogue_aps(
        access_points=state.access_points,
        known_ssids=state.known_ssids,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "ap_count": len(state.access_points),
                "aps_sample": state.access_points[:5],
                "known_ssids": state.known_ssids,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ROGUE_DETECTION,
            user_prompt=(f"Detect rogue APs:\n{ctx}"),
            schema=RogueDetectionOutput,
        )
        if llm_out.rogue_aps:  # type: ignore[union-attr]
            rogues = [
                *rogues,
                *llm_out.rogue_aps,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="detect_rogues",
            rogues=len(llm_out.rogue_aps),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_rogues",
        )

    step = _step(
        state.reasoning_chain,
        "detect_rogues",
        (f"Checking {len(state.access_points)} APs against {len(state.known_ssids)} known SSIDs"),
        f"Detected {len(rogues)} rogue APs",
        start,
        "rogue_detector",
    )

    return {
        "rogue_detections": rogues,
        "rogue_count": len(rogues),
        "stage": WSAStage.DETECT_ROGUES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_rogues",
    }


# ------------------------------------------------------------------
# Node: assess_risk
# ------------------------------------------------------------------


async def assess_risk(
    state: WirelessSecurityAuditorState,
) -> dict[str, Any]:
    """Assess overall wireless security risk."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    risk = await toolkit.assess_risk(
        encryption_findings=state.encryption_findings,
        rogue_detections=state.rogue_detections,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "encryption_count": len(state.encryption_findings),
                "rogue_count": state.rogue_count,
                "non_compliant": state.non_compliant_count,
                "encryption_sample": (state.encryption_findings[:5]),
                "rogue_sample": (state.rogue_detections[:5]),
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_RISK_ASSESSMENT,
            user_prompt=f"Assess wireless risk:\n{ctx}",
            schema=WirelessRiskOutput,
        )
        if isinstance(llm_out, WirelessRiskOutput):
            risk.update(
                {
                    "risk_score": llm_out.risk_score,
                    "critical_findings": llm_out.critical_findings,
                    "attack_vectors": llm_out.attack_vectors,
                    "compliance_gaps": llm_out.compliance_gaps,
                }
            )
        logger.info(
            "llm_enhanced",
            node="assess_risk",
            risk_score=llm_out.risk_score,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_risk",
        )

    step = _step(
        state.reasoning_chain,
        "assess_risk",
        (f"Assessing risk: {state.non_compliant_count} non-compliant, {state.rogue_count} rogues"),
        (f"Risk score: {risk.get('risk_score', 0):.1f}"),
        start,
        "risk_scorer",
    )

    return {
        "risk_assessment": risk,
        "risk_score": risk.get("risk_score", 0.0),
        "stage": WSAStage.ASSESS_RISK,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_risk",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: WirelessSecurityAuditorState,
) -> dict[str, Any]:
    """Generate the final wireless security audit report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    report: dict[str, Any] = {
        "site": state.site_name,
        "total_networks": state.total_networks,
        "total_aps": state.total_access_points,
        "rogue_count": state.rogue_count,
        "non_compliant": state.non_compliant_count,
        "risk_score": state.risk_score,
        "duration_ms": duration_ms,
    }

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "site": state.site_name,
                "total_networks": state.total_networks,
                "total_aps": state.total_access_points,
                "rogue_count": state.rogue_count,
                "non_compliant": state.non_compliant_count,
                "risk_score": state.risk_score,
                "risk_assessment": state.risk_assessment,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate wireless audit report:\n{ctx}"),
            schema=WirelessReportOutput,
        )
        if isinstance(llm_out, WirelessReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "recommendations": llm_out.recommendations,
                    "compliance_status": llm_out.compliance_status,
                    "effectiveness_rating": llm_out.effectiveness_rating,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                recs=len(llm_out.recommendations),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    await toolkit.record_metric(
        metric_name="wsa.run_completed",
        value=state.risk_score,
        tags={
            "rogues": str(state.rogue_count),
            "non_compliant": str(state.non_compliant_count),
        },
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        (f"Reporting on {state.total_access_points} APs, {state.rogue_count} rogues"),
        (f"Report generated, risk={state.risk_score:.1f}"),
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": WSAStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
