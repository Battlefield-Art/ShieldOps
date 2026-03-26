"""Node implementations for the Multi-Agent Security LangGraph workflow."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.multi_agent_security.models import (
    MultiAgentSecurityState,
    ReasoningStep,
)
from shieldops.agents.multi_agent_security.prompts import (
    SYSTEM_ANALYZE,
    SYSTEM_REPORT,
    InteractionAnalysisOutput,
    SecurityReportOutput,
)
from shieldops.agents.multi_agent_security.tools import MultiAgentSecurityToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: MultiAgentSecurityToolkit | None = None


def set_toolkit(toolkit: MultiAgentSecurityToolkit) -> None:
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> MultiAgentSecurityToolkit:
    if _toolkit is None:
        return MultiAgentSecurityToolkit()
    return _toolkit


# ------------------------------------------------------------------
# Node: discover_interactions
# ------------------------------------------------------------------


async def discover_interactions(state: MultiAgentSecurityState) -> dict[str, Any]:
    """Discover all agent-to-agent interactions within the scan scope."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    interactions = await toolkit.discover_interactions(
        state.scan_scope,
        state.agent_registry,
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="discover_interactions",
        input_summary=(f"Scanning scope with {len(state.agent_registry)} registered agents"),
        output_summary=f"Discovered {len(interactions)} agent-to-agent interactions",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="message_bus",
    )

    return {
        "interactions": interactions,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "discover_interactions",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: map_trust_chains
# ------------------------------------------------------------------


async def map_trust_chains(state: MultiAgentSecurityState) -> dict[str, Any]:
    """Build and evaluate delegation trust chains from observed interactions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    chains = await toolkit.map_trust_chains(state.interactions)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="map_trust_chains",
        input_summary=f"Mapping trust chains from {len(state.interactions)} interactions",
        output_summary=(
            f"Mapped {len(chains)} trust chains, "
            f"{sum(1 for c in chains if c.get('trust_level') in ('untrusted', 'compromised'))} "
            f"flagged"
        ),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="identity_registry",
    )

    return {
        "trust_chains": chains,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "map_trust_chains",
    }


# ------------------------------------------------------------------
# Node: verify_communications
# ------------------------------------------------------------------


async def verify_communications(state: MultiAgentSecurityState) -> dict[str, Any]:
    """Verify message integrity and agent identity for each interaction."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.verify_communications(state.interactions)

    failures = sum(1 for r in results if not r.get("identity_verified") or r.get("replay_detected"))

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="verify_communications",
        input_summary=f"Verifying {len(state.interactions)} communications",
        output_summary=f"Verified {len(results)} messages, {failures} failures",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="crypto_verifier",
    )

    return {
        "verification_results": results,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "verify_communications",
    }


# ------------------------------------------------------------------
# Node: detect_anomalies
# ------------------------------------------------------------------


async def detect_anomalies(state: MultiAgentSecurityState) -> dict[str, Any]:
    """Detect security anomalies across interactions, trust chains, and verifications."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    anomalies = await toolkit.detect_anomalies(
        state.interactions,
        state.trust_chains,
        state.verification_results,
    )

    # LLM enhancement: deeper interaction analysis
    try:
        context = _json.dumps(
            {
                "interactions": state.interactions[:10],
                "trust_chains": state.trust_chains[:10],
                "verification_failures": [
                    v for v in state.verification_results if not v.get("identity_verified")
                ][:10],
                "anomaly_count": len(anomalies),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ANALYZE,
            user_prompt=f"Multi-agent interaction context:\n{context}",
            schema=InteractionAnalysisOutput,
        )
        if hasattr(llm_result, "high_risk_pairs"):
            for pair in llm_result.high_risk_pairs:
                anomalies.append(
                    {
                        "anomaly_id": f"anom-llm-{len(anomalies)}",
                        "anomaly_type": "llm_identified_risk",
                        "severity": "high",
                        "description": f"LLM-identified high-risk pair: {pair}",
                        "source_agent": pair.split("->")[0].strip() if "->" in pair else "",
                        "target_agent": pair.split("->")[1].strip() if "->" in pair else "",
                        "confidence": llm_result.risk_score,
                        "mitre_technique": "",
                        "evidence": ["llm_analysis"],
                    }
                )
        logger.info(
            "llm_enhanced",
            node="detect_anomalies",
            llm_risk_score=getattr(llm_result, "risk_score", 0.0),
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="detect_anomalies")

    threats_detected = len(anomalies) > 0

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="detect_anomalies",
        input_summary=(
            f"Analysing {len(state.interactions)} interactions, "
            f"{len(state.trust_chains)} chains, "
            f"{len(state.verification_results)} verifications"
        ),
        output_summary=f"Detected {len(anomalies)} anomalies, threats={threats_detected}",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )

    return {
        "anomalies": anomalies,
        "threats_detected": threats_detected,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_anomalies",
    }


# ------------------------------------------------------------------
# Node: enforce_policies
# ------------------------------------------------------------------


async def enforce_policies(state: MultiAgentSecurityState) -> dict[str, Any]:
    """Enforce security policies based on detected anomalies."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    result = await toolkit.enforce_policies(state.anomalies, state.interactions)

    actions = result.get("actions", [])
    blocked = result.get("blocked_interactions", 0)
    quarantined = result.get("quarantined_agents", [])

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="enforce_policies",
        input_summary=f"Enforcing policies for {len(state.anomalies)} anomalies",
        output_summary=(
            f"{len(actions)} enforcement actions, {blocked} blocked, {len(quarantined)} quarantined"
        ),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="policy_engine",
    )

    return {
        "enforcement_actions": actions,
        "blocked_interactions": blocked,
        "quarantined_agents": quarantined,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "enforce_policies",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(state: MultiAgentSecurityState) -> dict[str, Any]:
    """Generate the final multi-agent security report."""
    start = datetime.now(UTC)

    total_interactions = len(state.interactions)
    total_anomalies = len(state.anomalies)
    critical_count = sum(1 for a in state.anomalies if a.get("severity") == "critical")
    high_count = sum(1 for a in state.anomalies if a.get("severity") == "high")

    # Risk score heuristic
    if critical_count >= 2:
        risk_score = min(1.0, 0.7 + critical_count * 0.1)
        risk_level = "critical"
    elif critical_count >= 1:
        risk_score = 0.7
        risk_level = "high"
    elif high_count >= 2:
        risk_score = 0.5
        risk_level = "medium"
    elif total_anomalies > 0:
        risk_score = 0.3
        risk_level = "low"
    else:
        risk_score = 0.1
        risk_level = "low"

    # Trust chain integrity
    compromised = sum(
        1 for c in state.trust_chains if c.get("trust_level") in ("untrusted", "compromised")
    )
    if compromised == 0:
        chain_integrity = "intact"
    elif compromised <= len(state.trust_chains) / 2:
        chain_integrity = "degraded"
    else:
        chain_integrity = "broken"

    report: dict[str, Any] = {
        "overall_risk": risk_level,
        "risk_score": round(risk_score, 2),
        "trust_chain_integrity": chain_integrity,
        "total_interactions": total_interactions,
        "total_anomalies": total_anomalies,
        "critical_anomalies": critical_count,
        "high_anomalies": high_count,
        "blocked_interactions": state.blocked_interactions,
        "quarantined_agents": state.quarantined_agents,
        "anomaly_types": sorted({a.get("anomaly_type", "") for a in state.anomalies}),
        "enforcement_actions_taken": len(state.enforcement_actions),
    }

    # LLM enhancement: richer report narrative
    try:
        report_context = _json.dumps(
            {
                "interactions_count": total_interactions,
                "anomalies": state.anomalies[:15],
                "trust_chains": state.trust_chains[:10],
                "enforcement_actions": state.enforcement_actions[:10],
                "risk_score": risk_score,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Security analysis context:\n{report_context}",
            schema=SecurityReportOutput,
        )
        report["threats_summary"] = getattr(llm_result, "threats_summary", "")
        report["recommendations"] = getattr(llm_result, "recommendations", [])
        report["compliance_notes"] = getattr(llm_result, "compliance_notes", [])
        logger.info("llm_enhanced", node="generate_report", overall_risk=risk_level)
    except Exception:
        logger.debug("llm_enhancement_skipped", node="generate_report")
        report["threats_summary"] = (
            f"{total_anomalies} anomalies detected across {total_interactions} "
            f"interactions. {critical_count} critical, {high_count} high severity."
        )
        report["recommendations"] = []
        report["compliance_notes"] = []

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary=(f"Generating report: {total_anomalies} anomalies, risk={risk_level}"),
        output_summary=(
            f"Report complete: risk={risk_level}, integrity={chain_integrity}, "
            f"score={risk_score:.2f}"
        ),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )

    return {
        "report": report,
        "risk_score": risk_score,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
