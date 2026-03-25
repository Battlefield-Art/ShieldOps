"""Shadow AI Discovery Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    DiscoveryStage,
    GovernanceStatus,
    ShadowAIAsset,
    TrafficPattern,
)
from .prompts import (
    SYSTEM_ASSET_CLASSIFICATION,
    SYSTEM_GOVERNANCE_PLANNING,
    SYSTEM_RISK_ASSESSMENT,
    SYSTEM_TRAFFIC_ANALYSIS,
    AssetClassificationOutput,
    GovernanceOutput,
    RiskAssessmentOutput,
    TrafficAnalysisOutput,
)
from .tools import ShadowAIDiscoveryToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def scan_network(
    state: dict[str, Any],
    toolkit: ShadowAIDiscoveryToolkit,
) -> dict[str, Any]:
    """Scan network traffic for AI-related service patterns."""
    logger.info("shadow_ai_discovery.node.scan_network")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")
    scope = state.get("scan_scope", ["all"])
    session_start = time.time()

    patterns = await toolkit.scan_network_traffic(
        tenant_id=tenant_id,
        scope=scope,
    )

    pattern_dicts = [p.model_dump() for p in patterns]
    llm_count = sum(1 for p in patterns if p.is_llm_traffic)

    return {
        "traffic_patterns": pattern_dicts,
        "stage": DiscoveryStage.ANALYZE_TRAFFIC.value,
        "session_start": session_start,
        "current_step": "scan_network",
        "stats": {
            "total_patterns": len(patterns),
            "llm_patterns": llm_count,
            "non_llm_patterns": len(patterns) - llm_count,
        },
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Scanned network: {len(patterns)} traffic patterns found ({llm_count} LLM)"],
    }


async def analyze_traffic(
    state: dict[str, Any],
    toolkit: ShadowAIDiscoveryToolkit,
) -> dict[str, Any]:
    """Analyze traffic patterns using LLM for deeper classification."""
    logger.info("shadow_ai_discovery.node.analyze_traffic")
    state = _to_dict(state)
    patterns = state.get("traffic_patterns", [])
    stats = state.get("stats", {})

    # Use LLM to analyze traffic patterns
    pattern_summary = json.dumps(patterns[:20], indent=2, default=str)
    try:
        analysis = await llm_structured(
            system_prompt=SYSTEM_TRAFFIC_ANALYSIS,
            user_prompt=(
                f"Analyze these {len(patterns)} network traffic patterns "
                f"for AI service detection:\n{pattern_summary}"
            ),
            response_model=TrafficAnalysisOutput,
        )
        analysis_dict = analysis.model_dump()
        stats["traffic_analysis"] = analysis_dict
        reasoning = (
            f"Traffic analysis: {analysis.llm_traffic_count} LLM, "
            f"{analysis.mcp_traffic_count} MCP, {analysis.vector_db_count} vector DB "
            f"(confidence {analysis.confidence:.0%})"
        )
    except Exception:
        logger.exception("shadow_ai_discovery.analyze_traffic.llm_error")
        llm_count = sum(1 for p in patterns if p.get("is_llm_traffic", False))
        stats["traffic_analysis"] = {
            "summary": "LLM analysis unavailable — using heuristic classification",
            "llm_traffic_count": llm_count,
            "confidence": 0.6,
        }
        reasoning = f"Traffic analysis (heuristic fallback): {llm_count} LLM patterns"

    return {
        "stage": DiscoveryStage.IDENTIFY_AGENTS.value,
        "current_step": "analyze_traffic",
        "stats": stats,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning],
    }


async def identify_agents(
    state: dict[str, Any],
    toolkit: ShadowAIDiscoveryToolkit,
) -> dict[str, Any]:
    """Identify and classify AI assets from traffic patterns."""
    logger.info("shadow_ai_discovery.node.identify_agents")
    state = _to_dict(state)
    raw_patterns = state.get("traffic_patterns", [])
    stats = state.get("stats", {})

    # Reconstruct TrafficPattern objects
    patterns = [TrafficPattern(**p) for p in raw_patterns]
    assets = await toolkit.identify_ai_assets(patterns)
    asset_dicts = [a.model_dump() for a in assets]

    # Use LLM to enhance classification
    asset_summary = json.dumps(asset_dicts[:15], indent=2, default=str)
    try:
        classification = await llm_structured(
            system_prompt=SYSTEM_ASSET_CLASSIFICATION,
            user_prompt=(f"Classify these {len(assets)} discovered AI assets:\n{asset_summary}"),
            response_model=AssetClassificationOutput,
        )
        stats["asset_classification"] = classification.model_dump()
        reasoning = (
            f"Identified {classification.total_assets} assets: "
            f"{classification.unmanaged_count} unmanaged, "
            f"{classification.shadow_count} shadow, "
            f"{classification.rogue_count} rogue"
        )
    except Exception:
        logger.exception("shadow_ai_discovery.identify_agents.llm_error")
        unmanaged = sum(1 for a in assets if a.governance_status == GovernanceStatus.UNMANAGED)
        shadow = sum(1 for a in assets if a.governance_status == GovernanceStatus.SHADOW)
        stats["asset_classification"] = {
            "summary": "LLM classification unavailable — using heuristic",
            "total_assets": len(assets),
            "unmanaged_count": unmanaged,
            "shadow_count": shadow,
        }
        reasoning = (
            f"Identified {len(assets)} assets (heuristic): {unmanaged} unmanaged, {shadow} shadow"
        )

    return {
        "discovered_assets": asset_dicts,
        "stage": DiscoveryStage.CLASSIFY_RISK.value,
        "current_step": "identify_agents",
        "stats": stats,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning],
    }


async def classify_risk(
    state: dict[str, Any],
    toolkit: ShadowAIDiscoveryToolkit,
) -> dict[str, Any]:
    """Classify risk for all discovered AI assets."""
    logger.info("shadow_ai_discovery.node.classify_risk")
    state = _to_dict(state)
    raw_assets = state.get("discovered_assets", [])
    stats = state.get("stats", {})

    assets = [ShadowAIAsset(**a) for a in raw_assets]
    scored = await toolkit.classify_risk(assets)
    scored_dicts = [a.model_dump() for a in scored]

    # Use LLM for risk assessment
    scored_summary = json.dumps(scored_dicts[:15], indent=2, default=str)
    try:
        risk = await llm_structured(
            system_prompt=SYSTEM_RISK_ASSESSMENT,
            user_prompt=(
                f"Assess risk for these {len(scored)} shadow AI assets:\n{scored_summary}"
            ),
            response_model=RiskAssessmentOutput,
        )
        stats["risk_assessment"] = risk.model_dump()
        reasoning = (
            f"Risk assessment: {risk.overall_risk_level} overall, "
            f"{len(risk.critical_assets)} critical, "
            f"${risk.cost_exposure:,.0f}/mo exposure"
        )
    except Exception:
        logger.exception("shadow_ai_discovery.classify_risk.llm_error")
        high = sum(1 for a in scored if a.risk_score >= 0.7)
        cost = sum(a.estimated_monthly_cost for a in scored)
        stats["risk_assessment"] = {
            "summary": "LLM risk assessment unavailable — using heuristic",
            "overall_risk_level": "high" if high > 0 else "medium",
            "critical_assets": [a.id for a in scored if a.risk_score >= 0.7],
            "cost_exposure": cost,
        }
        reasoning = f"Risk classified (heuristic): {high} high-risk, ${cost:,.0f}/mo exposure"

    return {
        "discovered_assets": scored_dicts,
        "stage": DiscoveryStage.RECOMMEND_GOVERNANCE.value,
        "current_step": "classify_risk",
        "stats": stats,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning],
    }


async def recommend_governance(
    state: dict[str, Any],
    toolkit: ShadowAIDiscoveryToolkit,
) -> dict[str, Any]:
    """Generate governance recommendations for unmanaged/rogue assets."""
    logger.info("shadow_ai_discovery.node.recommend_governance")
    state = _to_dict(state)
    raw_assets = state.get("discovered_assets", [])
    stats = state.get("stats", {})

    assets = [ShadowAIAsset(**a) for a in raw_assets]
    recommendations = await toolkit.generate_governance_plan(assets)
    rec_dicts = [r.model_dump() for r in recommendations]

    # Use LLM for governance planning
    rec_summary = json.dumps(rec_dicts[:15], indent=2, default=str)
    try:
        governance = await llm_structured(
            system_prompt=SYSTEM_GOVERNANCE_PLANNING,
            user_prompt=(
                f"Create governance plan for {len(recommendations)} recommendations:\n{rec_summary}"
            ),
            response_model=GovernanceOutput,
        )
        stats["governance_plan"] = governance.model_dump()
        reasoning = (
            f"Governance plan: {governance.block_count} block, "
            f"{governance.review_count} review, "
            f"{governance.onboard_count} onboard"
        )
    except Exception:
        logger.exception("shadow_ai_discovery.recommend_governance.llm_error")
        block_count = sum(1 for r in recommendations if r.action == "block")
        review_count = sum(1 for r in recommendations if r.action == "review_and_register")
        onboard_count = sum(1 for r in recommendations if r.action == "onboard")
        stats["governance_plan"] = {
            "summary": "LLM governance planning unavailable — using heuristic",
            "block_count": block_count,
            "review_count": review_count,
            "onboard_count": onboard_count,
        }
        reasoning = (
            f"Governance (heuristic): {block_count} block, "
            f"{review_count} review, {onboard_count} onboard"
        )

    return {
        "governance_recommendations": rec_dicts,
        "stage": DiscoveryStage.REPORT.value,
        "current_step": "recommend_governance",
        "stats": stats,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: ShadowAIDiscoveryToolkit,
) -> dict[str, Any]:
    """Generate final discovery report with all findings."""
    logger.info("shadow_ai_discovery.node.generate_report")
    state = _to_dict(state)
    session_start = state.get("session_start", time.time())
    duration_ms = (time.time() - session_start) * 1000

    assets = state.get("discovered_assets", [])
    recommendations = state.get("governance_recommendations", [])
    stats = state.get("stats", {})

    # Final summary stats
    stats["final_summary"] = {
        "total_assets_discovered": len(assets),
        "total_recommendations": len(recommendations),
        "unmanaged_assets": sum(1 for a in assets if a.get("governance_status") == "unmanaged"),
        "shadow_assets": sum(1 for a in assets if a.get("governance_status") == "shadow"),
        "rogue_assets": sum(1 for a in assets if a.get("governance_status") == "rogue"),
        "high_risk_assets": sum(1 for a in assets if a.get("risk_score", 0) >= 0.7),
        "total_monthly_cost_exposure": round(
            sum(a.get("estimated_monthly_cost", 0) for a in assets), 2
        ),
    }

    reasoning_chain = state.get("reasoning_chain", [])
    reasoning_chain.append(
        f"Report complete: {len(assets)} assets, "
        f"{len(recommendations)} recommendations, "
        f"{duration_ms:.0f}ms"
    )

    return {
        "stage": DiscoveryStage.REPORT.value,
        "current_step": "generate_report",
        "session_duration_ms": duration_ms,
        "stats": stats,
        "reasoning_chain": reasoning_chain,
    }
