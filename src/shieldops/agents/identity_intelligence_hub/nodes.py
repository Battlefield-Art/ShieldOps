"""Node implementations for the Identity Intelligence Hub."""

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.identity_intelligence_hub.models import (
    ActionRecommendation,
    CorrelatedIdentity,
    IdentityIntelligenceHubState,
    IdentityRiskAssessment,
    IdentitySignal,
    IdentityType,
    ReasoningStep,
    ThreatDetection,
    ThreatIndicator,
)
from shieldops.agents.identity_intelligence_hub.prompts import (
    SYSTEM_ASSESS,
    SYSTEM_COLLECT,
    SYSTEM_CORRELATE,
    SYSTEM_DETECT,
    SYSTEM_RECOMMEND,
    SYSTEM_REPORT,
    ActionOutput,
    CorrelationOutput,
    SignalCollectionOutput,
    ThreatDetectionOutput,
)
from shieldops.agents.identity_intelligence_hub.tools import (
    IdentityIntelligenceHubToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: IdentityIntelligenceHubToolkit | None = None


def _get_toolkit() -> IdentityIntelligenceHubToolkit:
    if _toolkit is None:
        return IdentityIntelligenceHubToolkit()
    return _toolkit


# ── Node: collect_identity_signals ────────────────────────


async def collect_identity_signals(
    state: IdentityIntelligenceHubState,
) -> dict[str, Any]:
    """Collect identity signals from all sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    idp_signals = await toolkit.collect_idp_signals(
        state.config,
    )
    iam_signals = await toolkit.collect_iam_signals(
        state.config,
    )
    agent_signals = await toolkit.collect_agent_signals(
        state.config,
    )

    all_raw = idp_signals + iam_signals + agent_signals
    signals = [IdentitySignal(**s).model_dump() for s in all_raw if isinstance(s, dict)]

    # Seed default signals when none collected
    scope = state.config.get("scope", "")
    if not signals and scope:
        for itype in [
            IdentityType.HUMAN_USER,
            IdentityType.SERVICE_ACCOUNT,
            IdentityType.AI_AGENT,
        ]:
            signals.append(
                IdentitySignal(
                    signal_id=f"sig-{itype.value[:4]}-001",
                    source="seed",
                    identity_type=itype,
                    principal=f"{itype.value}@{scope}",
                ).model_dump()
            )

    # LLM enhancement
    try:
        import json as _json

        ctx = _json.dumps(
            {
                "tenant_id": state.tenant_id,
                "scope": scope,
                "signals_found": len(signals),
                "sources": ["idp", "iam", "agent_registry"],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_COLLECT,
            user_prompt=(f"Signal collection context:\n{ctx}"),
            schema=SignalCollectionOutput,
        )
        logger.info(
            "llm_enhanced",
            node="collect_identity_signals",
            sources=getattr(llm_out, "sources_covered", 0),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="collect_identity_signals",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="collect_identity_signals",
        input_summary=f"Collecting from scope={scope}",
        output_summary=(f"Collected {len(signals)} signals"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="idp_connector",
    )

    await toolkit.record_metric("signals_collected", float(len(signals)))

    return {
        "signals_collected": signals,
        "total_signals": len(signals),
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_identity_signals",
        "session_start": start,
    }


# ── Node: correlate_identities ───────────────────────────


async def correlate_identities(
    state: IdentityIntelligenceHubState,
) -> dict[str, Any]:
    """Correlate identities across sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw_correlated = await toolkit.correlate_identities(
        state.signals_collected,
    )
    _graph = await toolkit.build_identity_graph(
        raw_correlated,
    )

    correlated = [
        CorrelatedIdentity(**c).model_dump() for c in raw_correlated if isinstance(c, dict)
    ]

    # Seed defaults
    if not correlated:
        seen: dict[str, list[dict[str, Any]]] = {}
        for sig in state.signals_collected:
            principal = sig.get("principal", "unknown")
            if principal not in seen:
                seen[principal] = []
            seen[principal].append(sig)

        for principal, sigs in seen.items():
            itype = sigs[0].get(
                "identity_type",
                IdentityType.HUMAN_USER,
            )
            correlated.append(
                CorrelatedIdentity(
                    correlation_id=(f"cor-{principal[:8]}"),
                    identity_type=itype,
                    primary_principal=principal,
                    sources=[s.get("source", "") for s in sigs],
                    signal_count=len(sigs),
                    confidence=0.8,
                ).model_dump()
            )

    # LLM enhancement
    try:
        import json as _json

        ctx = _json.dumps(
            {
                "signal_count": state.total_signals,
                "correlated": len(correlated),
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_CORRELATE,
            user_prompt=f"Correlation context:\n{ctx}",
            schema=CorrelationOutput,
        )
        logger.info(
            "llm_enhanced",
            node="correlate_identities",
            nhi=getattr(llm_out, "nhi_count", 0),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="correlate_identities",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="correlate_identities",
        input_summary=(f"Correlating {state.total_signals} signals"),
        output_summary=(f"Correlated {len(correlated)} identities"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="identity_correlator",
    )

    return {
        "correlated_identities": correlated,
        "correlated_count": len(correlated),
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "correlate_identities",
    }


# ── Node: detect_threats ─────────────────────────────────


async def detect_threats(
    state: IdentityIntelligenceHubState,
) -> dict[str, Any]:
    """Detect identity-based threats."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw_threats = await toolkit.detect_threats(
        state.correlated_identities,
    )
    mapped = await toolkit.check_mitre_mapping(raw_threats)

    threats = [ThreatDetection(**t).model_dump() for t in mapped if isinstance(t, dict)]

    # Seed defaults
    if not threats:
        for identity in state.correlated_identities:
            itype = identity.get(
                "identity_type",
                IdentityType.HUMAN_USER,
            )
            if itype in (
                IdentityType.SERVICE_ACCOUNT,
                IdentityType.AI_AGENT,
            ):
                cid = identity.get("correlation_id", "")
                threats.append(
                    ThreatDetection(
                        detection_id=f"det-{cid}",
                        correlation_id=cid,
                        threat_type=(ThreatIndicator.EXCESSIVE_PERMISSIONS),
                        severity="medium",
                        principal=identity.get("primary_principal", ""),
                        confidence=0.6,
                    ).model_dump()
                )

    # LLM enhancement
    try:
        import json as _json

        ctx = _json.dumps(
            {
                "correlated": state.correlated_count,
                "threats_found": len(threats),
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_DETECT,
            user_prompt=(f"Threat detection context:\n{ctx}"),
            schema=ThreatDetectionOutput,
        )
        logger.info(
            "llm_enhanced",
            node="detect_threats",
            risk=getattr(llm_out, "risk_score", 0.0),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_threats",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="detect_threats",
        input_summary=(f"Scanning {state.correlated_count} identities"),
        output_summary=(f"Detected {len(threats)} threats"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="threat_engine",
    )

    return {
        "threats_detected": threats,
        "threat_count": len(threats),
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_threats",
    }


# ── Node: assess_risk ────────────────────────────────────


async def assess_risk(
    state: IdentityIntelligenceHubState,
) -> dict[str, Any]:
    """Assess risk for detected identity threats."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw_assessments = await toolkit.assess_identity_risk(
        state.threats_detected,
    )

    assessments = [
        IdentityRiskAssessment(**a).model_dump() for a in raw_assessments if isinstance(a, dict)
    ]

    # Seed defaults
    if not assessments:
        for threat in state.threats_detected:
            cid = threat.get("correlation_id", "")
            severity = threat.get("severity", "medium")
            score = 50.0
            if severity == "critical":
                score = 90.0
            elif severity == "high":
                score = 75.0
            assessments.append(
                IdentityRiskAssessment(
                    correlation_id=cid,
                    risk_score=score,
                    threat_count=1,
                    identity_type=threat.get(
                        "identity_type",
                        IdentityType.HUMAN_USER,
                    ),
                    exposure_level=severity,
                ).model_dump()
            )

    high_risk = sum(1 for a in assessments if a.get("risk_score", 0) >= 70.0)

    # LLM enhancement
    try:
        import json as _json

        ctx = _json.dumps(
            {
                "threats": state.threat_count,
                "assessments": len(assessments),
                "high_risk": high_risk,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ASSESS,
            user_prompt=f"Risk assessment context:\n{ctx}",
            schema=ThreatDetectionOutput,
        )
        logger.info(
            "llm_enhanced",
            node="assess_risk",
            risk=getattr(llm_out, "risk_score", 0.0),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_risk",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="assess_risk",
        input_summary=(f"Assessing {state.threat_count} threats"),
        output_summary=(f"Assessed {len(assessments)} identities, high_risk={high_risk}"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="risk_engine",
    )

    return {
        "risk_assessments": assessments,
        "high_risk_identities": high_risk,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_risk",
    }


# ── Node: recommend_actions ──────────────────────────────


async def recommend_actions(
    state: IdentityIntelligenceHubState,
) -> dict[str, Any]:
    """Generate action recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw_recs = await toolkit.generate_recommendations(
        state.risk_assessments,
    )

    recommendations = [
        ActionRecommendation(**r).model_dump() for r in raw_recs if isinstance(r, dict)
    ]

    # Seed defaults
    if not recommendations:
        for assessment in state.risk_assessments:
            cid = assessment.get("correlation_id", "")
            score = assessment.get("risk_score", 0)
            action = "monitor"
            if score >= 70.0:
                action = "revoke_and_rotate"
            elif score >= 50.0:
                action = "restrict_permissions"
            recommendations.append(
                ActionRecommendation(
                    recommendation_id=f"rec-{cid}",
                    correlation_id=cid,
                    action_type=action,
                    priority=("critical" if score >= 70.0 else "medium"),
                    automation_possible=(score >= 70.0),
                ).model_dump()
            )

    # LLM enhancement
    try:
        import json as _json

        ctx = _json.dumps(
            {
                "assessments": len(state.risk_assessments),
                "high_risk": state.high_risk_identities,
                "recommendations": len(recommendations),
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_RECOMMEND,
            user_prompt=(f"Action recommendation context:\n{ctx}"),
            schema=ActionOutput,
        )
        logger.info(
            "llm_enhanced",
            node="recommend_actions",
            urgent=getattr(llm_out, "urgent_count", 0),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="recommend_actions",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="recommend_actions",
        input_summary=(f"Generating actions for {state.high_risk_identities} high-risk"),
        output_summary=(f"Created {len(recommendations)} actions"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="recommendation_engine",
    )

    return {
        "recommendations": recommendations,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "recommend_actions",
    }


# ── Node: generate_report ────────────────────────────────


async def generate_report(
    state: IdentityIntelligenceHubState,
) -> dict[str, Any]:
    """Generate final identity intelligence report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report_data: dict[str, Any] = {
        "request_id": state.request_id,
        "tenant_id": state.tenant_id,
        "total_signals": state.total_signals,
        "correlated_count": state.correlated_count,
        "threat_count": state.threat_count,
        "high_risk_identities": (state.high_risk_identities),
        "recommendations": len(state.recommendations),
        "duration_ms": duration_ms,
    }

    # LLM enhancement
    try:
        import json as _json

        ctx = _json.dumps(report_data, default=str)
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Identity intelligence report:\n{ctx}"),
            schema=SignalCollectionOutput,
        )
        report_data["llm_summary"] = getattr(llm_out, "summary", "")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    await toolkit.record_metric("threat_count", float(state.threat_count))
    await toolkit.record_metric("duration_ms", float(duration_ms))

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary=(f"Generating report for {state.request_id}"),
        output_summary=(f"Complete in {duration_ms}ms, threats={state.threat_count}"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used=None,
    )

    return {
        "report": report_data,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
