"""Node implementations for the Unified Threat Model."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.unified_threat_model.models import (
    ReasoningStep,
    UnifiedThreatModelState,
    UTMStage,
)
from shieldops.agents.unified_threat_model.prompts import (
    SYSTEM_CONTROLS,
    SYSTEM_PRIORITIZE,
    SYSTEM_RISK,
    SYSTEM_SCOPE,
    SYSTEM_THREATS,
    ControlAnalysisOutput,
    MitigationOutput,
    RiskCalculationOutput,
    ScopeDefinitionOutput,
    ThreatIdentificationOutput,
)
from shieldops.agents.unified_threat_model.tools import (
    UnifiedThreatModelToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: UnifiedThreatModelToolkit | None = None


def set_toolkit(
    toolkit: UnifiedThreatModelToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> UnifiedThreatModelToolkit:
    if _toolkit is None:
        return UnifiedThreatModelToolkit()
    return _toolkit


def _step(
    state: UnifiedThreatModelState,
    action: str,
    input_summary: str,
    output_summary: str,
    duration_ms: int,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Create a reasoning step."""
    return ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=duration_ms,
        tool_used=tool_used,
    )


async def define_scope(
    state: UnifiedThreatModelState,
) -> dict[str, Any]:
    """Define the threat modeling scope."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.define_scope(state.config)
    asset_count = sum(len(s.get("assets", [])) for s in raw)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "scope": state.config.get("scope", ""),
                "assets": state.config.get("assets", [])[:10],
                "scope_count": len(raw),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_SCOPE,
            user_prompt=(f"Scope definition context:\n{ctx}"),
            schema=ScopeDefinitionOutput,
        )
        if hasattr(llm_result, "total_assets") and llm_result.total_assets > asset_count:
            asset_count = llm_result.total_assets
        logger.info(
            "llm_enhanced",
            node="define_scope",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="define_scope",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "define_scope",
        f"scope={state.config.get('scope', '')}",
        f"defined scope with {asset_count} assets",
        elapsed,
        "asset_inventory",
    )
    await toolkit.record_metric("scope_assets", float(asset_count))

    return {
        "threat_scope": raw,
        "asset_count": asset_count,
        "stage": UTMStage.IDENTIFY_THREATS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "define_scope",
        "session_start": start,
    }


async def identify_threats(
    state: UnifiedThreatModelState,
) -> dict[str, Any]:
    """Identify threats using STRIDE methodology."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    threats = await toolkit.identify_threats(
        state.threat_scope,
    )
    t_count = len(threats)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "scope_count": len(state.threat_scope),
                "threats": threats[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_THREATS,
            user_prompt=(f"Threat identification:\n{ctx}"),
            schema=ThreatIdentificationOutput,
        )
        if hasattr(llm_result, "threats_found") and llm_result.threats_found > t_count:
            t_count = llm_result.threats_found
        logger.info(
            "llm_enhanced",
            node="identify_threats",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="identify_threats",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "identify_threats",
        f"analyzing {len(state.threat_scope)} scopes",
        f"{t_count} threats identified",
        elapsed,
        "threat_library",
    )

    return {
        "identified_threats": threats,
        "threat_count": t_count,
        "stage": UTMStage.ANALYZE_CONTROLS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "identify_threats",
    }


async def analyze_controls(
    state: UnifiedThreatModelState,
) -> dict[str, Any]:
    """Analyze existing security controls."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    analyses = await toolkit.analyze_controls(
        state.identified_threats,
    )
    gaps = sum(1 for a in analyses if a.get("gaps"))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "threat_count": len(state.identified_threats),
                "controls": analyses[:10],
                "gaps": gaps,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CONTROLS,
            user_prompt=(f"Control analysis:\n{ctx}"),
            schema=ControlAnalysisOutput,
        )
        if hasattr(llm_result, "gaps_found") and llm_result.gaps_found > gaps:
            gaps = llm_result.gaps_found
        logger.info(
            "llm_enhanced",
            node="analyze_controls",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_controls",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "analyze_controls",
        f"analyzing controls for {len(state.identified_threats)} threats",
        f"{len(analyses)} controls, {gaps} gaps",
        elapsed,
        "control_catalog",
    )

    return {
        "control_analyses": analyses,
        "control_gaps": gaps,
        "stage": UTMStage.CALCULATE_RISK,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "analyze_controls",
    }


async def calculate_risk(
    state: UnifiedThreatModelState,
) -> dict[str, Any]:
    """Calculate risk scores for threats."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    calculations = await toolkit.calculate_risk(
        state.identified_threats,
        state.control_analyses,
    )
    max_score = max(
        (c.get("risk_score", 0.0) for c in calculations),
        default=0.0,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "threat_count": len(state.identified_threats),
                "calculations": calculations[:10],
                "max_score": max_score,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_RISK,
            user_prompt=(f"Risk calculation context:\n{ctx}"),
            schema=RiskCalculationOutput,
        )
        if hasattr(llm_result, "max_risk_score") and llm_result.max_risk_score > max_score:
            max_score = round(
                (max_score + llm_result.max_risk_score) / 2,
                1,
            )
        logger.info(
            "llm_enhanced",
            node="calculate_risk",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="calculate_risk",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "calculate_risk",
        f"calculating risk for {len(state.identified_threats)} threats",
        f"max_risk={max_score}",
        elapsed,
        "risk_engine",
    )
    await toolkit.record_metric("max_risk", max_score)

    return {
        "risk_calculations": calculations,
        "max_risk_score": max_score,
        "stage": UTMStage.PRIORITIZE,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "calculate_risk",
    }


async def prioritize_mitigations(
    state: UnifiedThreatModelState,
) -> dict[str, Any]:
    """Prioritize mitigation recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    mitigations = await toolkit.prioritize_mitigations(
        state.risk_calculations,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "risk_count": len(state.risk_calculations),
                "mitigations": mitigations[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_PRIORITIZE,
            user_prompt=(f"Mitigation prioritization:\n{ctx}"),
            schema=MitigationOutput,
        )
        if hasattr(llm_result, "mitigations"):
            logger.info(
                "llm_enhanced",
                node="prioritize_mitigations",
                llm_mits=len(llm_result.mitigations),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="prioritize_mitigations",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "prioritize_mitigations",
        f"prioritizing for {len(state.risk_calculations)} risks",
        f"created {len(mitigations)} mitigations",
        elapsed,
        "mitigation_engine",
    )

    return {
        "prioritized_mitigations": mitigations,
        "stage": UTMStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "prioritize_mitigations",
    }


async def generate_report(
    state: UnifiedThreatModelState,
) -> dict[str, Any]:
    """Generate final threat model report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int(
            (datetime.now(UTC) - state.session_start).total_seconds() * 1000,
        )

    report = {
        "request_id": state.request_id,
        "assets_in_scope": state.asset_count,
        "threats_identified": state.threat_count,
        "control_gaps": state.control_gaps,
        "max_risk_score": state.max_risk_score,
        "mitigations": len(state.prioritized_mitigations),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric(
        "scan_duration_ms",
        float(duration_ms),
    )
    await toolkit.record_metric(
        "threats_identified",
        float(state.threat_count),
    )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "generate_report",
        f"finalizing model {state.request_id}",
        f"report complete in {duration_ms}ms",
        elapsed,
        None,
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "complete",
    }
