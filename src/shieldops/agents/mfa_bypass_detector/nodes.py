"""MFA Bypass Detector Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    AuthEvent,
    AuthPattern,
    BypassAttempt,
    MBDStage,
    ReasoningStep,
    RiskAssessment,
)
from .tools import MFABypassDetectorToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Collect Auth Events
# ------------------------------------------------------------------


async def collect_auth_events(
    state: dict[str, Any],
    toolkit: MFABypassDetectorToolkit,
) -> dict[str, Any]:
    """Collect authentication events from IdP/SIEM."""
    logger.info("mbd.node.collect_auth_events")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    events = await toolkit.collect_auth_events(tenant_id)
    data = [e.model_dump() for e in events]

    note = f"Collected {len(events)} auth events"

    return {
        "stage": MBDStage.ANALYZE_PATTERNS.value,
        "auth_events": data,
        "total_events_analyzed": len(events),
        "current_step": "collect_auth_events",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="collect_auth_events",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Analyze Patterns
# ------------------------------------------------------------------


async def analyze_patterns(
    state: dict[str, Any],
    toolkit: MFABypassDetectorToolkit,
) -> dict[str, Any]:
    """Analyze authentication patterns per user."""
    logger.info("mbd.node.analyze_patterns")
    state = _to_dict(state)

    events = [AuthEvent(**e) for e in state.get("auth_events", [])]
    patterns = await toolkit.analyze_patterns(events)
    data = [p.model_dump() for p in patterns]

    note = f"Identified {len(patterns)} user patterns"

    try:
        from .prompts import SYSTEM_ANALYZE, PatternInsight

        ctx = json.dumps(
            {
                "patterns": [
                    {
                        "user": p.user_id,
                        "attempts": p.total_attempts,
                        "failed_mfa": p.failed_mfa_count,
                        "geos": p.unique_geos,
                        "anomaly": p.session_anomaly_score,
                    }
                    for p in patterns[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            PatternInsight,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"Auth patterns:\n{ctx}",
                schema=PatternInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="mbd",
            node="analyze_patterns",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="mbd",
            node="analyze_patterns",
        )

    return {
        "stage": MBDStage.DETECT_BYPASS.value,
        "patterns": data,
        "current_step": "analyze_patterns",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="analyze_patterns",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Detect Bypass
# ------------------------------------------------------------------


async def detect_mfa_bypass(
    state: dict[str, Any],
    toolkit: MFABypassDetectorToolkit,
) -> dict[str, Any]:
    """Detect MFA bypass attempts from patterns."""
    logger.info("mbd.node.detect_bypass")
    state = _to_dict(state)

    patterns = [AuthPattern(**p) for p in state.get("patterns", [])]
    attempts = await toolkit.detect_mfa_bypass(patterns)
    data = [a.model_dump() for a in attempts]

    note = f"Detected {len(attempts)} bypass attempts across {len(patterns)} users"

    return {
        "stage": MBDStage.ASSESS_RISK.value,
        "bypass_attempts": data,
        "bypasses_detected": len(attempts),
        "current_step": "detect_bypass",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="detect_bypass",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Assess Risk
# ------------------------------------------------------------------


async def assess_risk(
    state: dict[str, Any],
    toolkit: MFABypassDetectorToolkit,
) -> dict[str, Any]:
    """Assess risk for each bypass attempt."""
    logger.info("mbd.node.assess_risk")
    state = _to_dict(state)

    attempts = [BypassAttempt(**a) for a in state.get("bypass_attempts", [])]
    assessments = await toolkit.assess_risk(attempts)
    data = [r.model_dump() for r in assessments]

    compromised = sum(1 for r in assessments if r.account_compromised)
    note = f"Assessed {len(assessments)} risks, {compromised} accounts compromised"

    return {
        "stage": MBDStage.REMEDIATE.value,
        "risk_assessments": data,
        "current_step": "assess_risk",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="assess_risk",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Remediate
# ------------------------------------------------------------------


async def apply_remediation(
    state: dict[str, Any],
    toolkit: MFABypassDetectorToolkit,
) -> dict[str, Any]:
    """Apply remediation actions."""
    logger.info("mbd.node.remediate")
    state = _to_dict(state)

    assessments = [RiskAssessment(**r) for r in state.get("risk_assessments", [])]
    remediations = await toolkit.apply_remediation(assessments)
    data = [r.model_dump() for r in remediations]

    applied = sum(1 for r in remediations if r.status == "applied")
    note = f"Applied {applied}/{len(remediations)} remediation actions"

    return {
        "stage": MBDStage.REPORT.value,
        "remediations": data,
        "current_step": "remediate",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="remediate",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: MFABypassDetectorToolkit,
) -> dict[str, Any]:
    """Compile the final MFA bypass detection report."""
    logger.info("mbd.node.report")
    state = _to_dict(state)

    total_events = state.get("total_events_analyzed", 0)
    bypass_count = state.get("bypasses_detected", 0)
    risk_count = len(state.get("risk_assessments", []))
    remediation_count = len(state.get("remediations", []))

    lines = [
        "# MFA Bypass Detection Report",
        "",
        f"**Events analyzed:** {total_events}",
        f"**Bypasses detected:** {bypass_count}",
        f"**Risk assessments:** {risk_count}",
        f"**Remediations applied:** {remediation_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "total_events": total_events,
                "bypasses": bypass_count,
                "risks": risk_count,
                "remediations": remediation_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=(f"MFA bypass report:\n{ctx}"),
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="mbd",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="mbd",
            node="report",
        )

    return {
        "stage": MBDStage.REPORT.value,
        "report": report_text,
        "current_step": "report",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="report",
                detail="Final report compiled",
                confidence=0.95,
            ).model_dump()
        ],
    }
