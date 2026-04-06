"""Node implementations for the SOC Analyst Agent LangGraph workflow."""

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.soc_analyst.models import (
    ContainmentRecommendation,
    CorrelatedEvent,
    ReasoningStep,
    SOCAnalystState,
    ThreatIntelEnrichment,
)
from shieldops.agents.soc_analyst.prompts import SYSTEM_NARRATIVE, AttackNarrativeOutput
from shieldops.agents.soc_analyst.tools import SOCAnalystToolkit
from shieldops.policy.engine import PolicyContext
from shieldops.policy.engine import evaluate as policy_evaluate
from shieldops.utils.llm import llm_structured
from shieldops.utils.persistence import persist_agent_run, write_audit_log

logger = structlog.get_logger()

_toolkit: SOCAnalystToolkit | None = None


def set_toolkit(toolkit: SOCAnalystToolkit) -> None:
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> SOCAnalystToolkit:
    if _toolkit is None:
        return SOCAnalystToolkit()
    return _toolkit


async def triage_alert(state: SOCAnalystState) -> dict[str, Any]:
    """Perform initial alert triage and scoring.

    Checks OPA policy before triage, uses LLM-enhanced severity classification
    with heuristic fallback.
    """
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    alert_data = state.alert_data

    # OPA policy check before triage action
    try:
        policy_decision = await policy_evaluate(
            action="triage_alert",
            context=PolicyContext(
                agent_name="soc_analyst",
                action_type="triage",
                target_resources=[state.alert_id],
                risk_score=0.1,  # read-only triage is low risk
            ),
        )
        if not policy_decision.allowed:
            logger.warning(
                "soc_analyst.triage_alert.policy_denied",
                alert_id=state.alert_id,
                reason=policy_decision.reason,
            )
            return {
                "error": f"Policy denied triage: {policy_decision.reason}",
                "current_step": "triage_alert",
                "session_start": start,
            }
    except Exception:
        logger.debug("soc_analyst.triage_alert.policy_check_skipped")

    # Use LLM-enhanced severity classification with heuristic fallback
    classification = await toolkit.classify_severity(alert_data)
    triage_score = classification.get("triage_score", 50.0)
    classified_severity = classification.get("classified_severity", "medium")

    # Determine tier
    if triage_score >= 85:
        tier = 3
    elif triage_score >= 60:
        tier = 2
    else:
        tier = 1

    # Check for suppression
    should_suppress = alert_data.get("known_false_positive", False) or triage_score < 15

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="triage_alert",
        input_summary=f"Alert {state.alert_id} severity={classified_severity}",
        output_summary=(
            f"Triage score={triage_score}, tier={tier}, suppress={should_suppress}, "
            f"method={classification.get('method', 'unknown')}"
        ),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="classify_severity",
    )

    await toolkit.record_soc_metric("triage", triage_score)

    return {
        "triage_score": triage_score,
        "tier": tier,
        "should_suppress": should_suppress,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "triage_alert",
        "session_start": start,
    }


async def enrich_alert(state: SOCAnalystState) -> dict[str, Any]:
    """Enrich alert with threat intelligence, AWS context, and CrowdStrike host data."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    # Extract indicators from alert data
    indicators = []
    for key in ("source_ip", "dest_ip", "domain", "file_hash", "url"):
        if value := state.alert_data.get(key):
            indicators.append(str(value))

    # Enrich with threat intelligence
    intel_data = await toolkit.enrich_with_threat_intel(indicators)
    enrichment = ThreatIntelEnrichment(**intel_data)

    # Enrich with AWS context if instance_id is present
    asset_context: dict[str, Any] = {}
    if instance_id := state.alert_data.get("instance_id"):
        aws_context = await toolkit.enrich_with_aws_context(instance_id)
        asset_context["aws"] = aws_context

    # Enrich with CrowdStrike host data if hostname is present
    if hostname := state.alert_data.get("hostname"):
        cs_host = await toolkit.enrich_with_crowdstrike_host(hostname)
        asset_context["crowdstrike_host"] = cs_host

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="enrich_alert",
        input_summary=f"Enriching {len(indicators)} indicators + asset context",
        output_summary=(
            f"IOC matches={len(enrichment.ioc_matches)}, "
            f"reputation={enrichment.reputation_score}, "
            f"asset_sources={list(asset_context.keys())}"
        ),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="threat_intel + aws + crowdstrike",
    )

    return {
        "threat_intel_enrichment": enrichment,
        "asset_context": asset_context,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "enrich_alert",
    }


async def correlate_events(state: SOCAnalystState) -> dict[str, Any]:
    """Find and correlate related events."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw_events = await toolkit.correlate_signals(state.alert_id)
    correlated = [CorrelatedEvent(**e) for e in raw_events if isinstance(e, dict)]

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="correlate_events",
        input_summary=f"Correlating events for alert {state.alert_id}",
        output_summary=f"Found {len(correlated)} correlated events",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="signal_correlator",
    )

    return {
        "correlated_events": correlated,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "correlate_events",
    }


async def map_attack_chain(state: SOCAnalystState) -> dict[str, Any]:
    """Map events to MITRE ATT&CK and build attack chain."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    events = [e.model_dump() for e in state.correlated_events]
    mitre_techniques = await toolkit.map_to_mitre(events)

    # Build attack chain from events + techniques
    attack_chain: list[dict[str, Any]] = []
    for event in state.correlated_events:
        attack_chain.append(
            {
                "event_id": event.event_id,
                "event_type": event.event_type,
                "timestamp": event.timestamp,
                "severity": event.severity,
            }
        )

    # LLM enhancement: deeper attack chain analysis
    try:
        import json as _json

        chain_context = _json.dumps(
            {
                "alert_id": state.alert_id,
                "tier": state.tier,
                "events": events[:20],
                "mitre_techniques": mitre_techniques[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_NARRATIVE,
            user_prompt=f"Attack chain context:\n{chain_context}",
            schema=AttackNarrativeOutput,
        )
        if hasattr(llm_result, "mitre_techniques") and llm_result.mitre_techniques:
            mitre_techniques = list({*mitre_techniques, *llm_result.mitre_techniques})
        logger.info(
            "llm_enhanced",
            node="map_attack_chain",
            severity=getattr(llm_result, "severity", "unknown"),
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="map_attack_chain")

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="map_attack_chain",
        input_summary=f"Mapping {len(events)} events to MITRE ATT&CK",
        output_summary=f"Identified {len(mitre_techniques)} techniques, "
        f"{len(attack_chain)} chain steps",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="mitre_mapper + chain_reconstructor",
    )

    return {
        "mitre_techniques": mitre_techniques,
        "attack_chain": attack_chain,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "map_attack_chain",
    }


async def generate_narrative(state: SOCAnalystState) -> dict[str, Any]:
    """Generate human-readable attack narrative."""
    start = datetime.now(UTC)

    # Build narrative from available data
    parts = [f"Alert {state.alert_id} — Tier {state.tier} Analysis"]
    if state.mitre_techniques:
        parts.append(f"MITRE techniques: {', '.join(state.mitre_techniques)}")
    if state.correlated_events:
        parts.append(f"Correlated events: {len(state.correlated_events)}")
    if state.threat_intel_enrichment and state.threat_intel_enrichment.ioc_matches:
        parts.append(f"IOC matches: {len(state.threat_intel_enrichment.ioc_matches)}")

    narrative = ". ".join(parts)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_narrative",
        input_summary=f"Building narrative from {len(state.attack_chain)} chain steps",
        output_summary=f"Generated narrative ({len(narrative)} chars)",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )

    return {
        "attack_narrative": narrative,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "generate_narrative",
    }


async def recommend_containment(state: SOCAnalystState) -> dict[str, Any]:
    """Recommend containment actions."""
    start = datetime.now(UTC)

    recommendations: list[ContainmentRecommendation] = []

    # Generate recommendations based on tier and severity
    if state.tier >= 2:
        recommendations.append(
            ContainmentRecommendation(
                action="isolate_host",
                target=state.alert_data.get("source_ip", "unknown"),
                urgency="high" if state.tier == 3 else "medium",
                risk_level="medium",
                automated=state.tier < 3,
                description="Isolate affected host from network",
            )
        )
    if state.threat_intel_enrichment and state.threat_intel_enrichment.ioc_matches:
        recommendations.append(
            ContainmentRecommendation(
                action="block_iocs",
                target="firewall",
                urgency="high",
                risk_level="low",
                automated=True,
                description="Block matched IOCs at firewall",
            )
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="recommend_containment",
        input_summary=f"Tier {state.tier} alert analysis complete",
        output_summary=f"Generated {len(recommendations)} containment recommendations",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="policy_engine",
    )

    return {
        "containment_recommendations": recommendations,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "recommend_containment",
    }


async def execute_playbook(state: SOCAnalystState) -> dict[str, Any]:
    """Execute automated playbook for auto-executable recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    auto_actions = [r for r in state.containment_recommendations if r.automated]
    result: dict[str, Any] = {}

    if auto_actions:
        result = await toolkit.execute_playbook(
            playbook_name="soc_auto_containment",
            parameters={
                "alert_id": state.alert_id,
                "actions": [a.model_dump() for a in auto_actions],
            },
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="execute_playbook",
        input_summary=f"Auto-executing {len(auto_actions)} actions",
        output_summary=f"Playbook result: {result.get('status', 'skipped')}",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="soar_engine",
    )

    return {
        "playbook_executed": bool(auto_actions),
        "playbook_result": result,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "execute_playbook",
    }


async def finalize(state: SOCAnalystState) -> dict[str, Any]:
    """Finalize analysis, persist results, and write audit log."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    await toolkit.record_soc_metric("analysis_duration_ms", float(duration_ms))

    # Persist agent run
    org_id = state.alert_data.get("org_id", "")
    try:
        await persist_agent_run(
            agent_name="soc_analyst",
            org_id=org_id,
            input_data={"alert_id": state.alert_id, "alert_data": state.alert_data},
            output_data={
                "tier": state.tier,
                "triage_score": state.triage_score,
                "containment_count": len(state.containment_recommendations),
                "mitre_techniques": state.mitre_techniques,
                "attack_narrative": state.attack_narrative[:500] if state.attack_narrative else "",
            },
            duration_ms=duration_ms,
            error_message=state.error or None,
        )
    except Exception:
        logger.debug("soc_analyst.finalize.persist_failed")

    # Write audit log
    try:
        await write_audit_log(
            action="soc_analyst.completed" if not state.error else "soc_analyst.failed",
            actor="soc_analyst-agent",
            target=state.alert_id,
            result=f"tier={state.tier}, score={state.triage_score}",
            org_id=org_id,
            metadata={
                "duration_ms": duration_ms,
                "containment_count": len(state.containment_recommendations),
            },
        )
    except Exception:
        logger.debug("soc_analyst.finalize.audit_failed")

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="finalize",
        input_summary=f"Finalizing Tier {state.tier} analysis",
        output_summary=f"Analysis complete in {duration_ms}ms, persisted",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used=None,
    )

    return {
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
