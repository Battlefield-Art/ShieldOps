"""Node implementations for the Threat Actor Profiler."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.threat_actor_profiler.models import (
    ReasoningStep,
    TAPStage,
    ThreatActorProfilerState,
)
from shieldops.agents.threat_actor_profiler.prompts import (
    SYSTEM_ASSESS_TARGETING,
    SYSTEM_BUILD_PROFILES,
    SYSTEM_CLUSTER_ACTIVITY,
    SYSTEM_COLLECT_INDICATORS,
    SYSTEM_MAP_TTPS,
    ClusteringOutput,
    IndicatorCollectionOutput,
    ProfileBuildOutput,
    TargetingOutput,
    TTPMappingOutput,
)
from shieldops.agents.threat_actor_profiler.tools import (
    ThreatActorProfilerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ThreatActorProfilerToolkit | None = None


def _get_toolkit() -> ThreatActorProfilerToolkit:
    if _toolkit is None:
        return ThreatActorProfilerToolkit()
    return _toolkit


def _step(
    state: ThreatActorProfilerState,
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


async def collect_indicators(
    state: ThreatActorProfilerState,
) -> dict[str, Any]:
    """Collect threat indicators from intelligence sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.collect_indicators(state.config)
    high_conf = sum(1 for i in raw if i.get("confidence") in ("confirmed", "high"))

    try:
        ctx = _json.dumps(
            {
                "sources": state.config.get("sources", []),
                "indicator_count": len(raw),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_COLLECT_INDICATORS,
            user_prompt=(f"Indicator collection context:\n{ctx}"),
            schema=IndicatorCollectionOutput,
        )
        if hasattr(llm_result, "total_indicators"):
            logger.info("llm_enhanced", node="collect_indicators")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="collect_indicators",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "collect_indicators",
        f"sources={state.config.get('sources', [])}",
        f"collected {len(raw)}, {high_conf} high-confidence",
        elapsed,
        "intel_client",
    )
    await toolkit.record_metric("indicators_collected", float(len(raw)))

    return {
        "indicators": raw,
        "stage": TAPStage.CLUSTER_ACTIVITY,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_indicators",
        "session_start": start,
    }


async def cluster_activity(
    state: ThreatActorProfilerState,
) -> dict[str, Any]:
    """Cluster related threat activity."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    clusters = await toolkit.cluster_activity(state.indicators)

    try:
        ctx = _json.dumps(
            {
                "indicator_count": len(state.indicators),
                "cluster_count": len(clusters),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CLUSTER_ACTIVITY,
            user_prompt=f"Activity clustering context:\n{ctx}",
            schema=ClusteringOutput,
        )
        if hasattr(llm_result, "total_clusters"):
            logger.info("llm_enhanced", node="cluster_activity")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="cluster_activity",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "cluster_activity",
        f"clustering {len(state.indicators)} indicators",
        f"{len(clusters)} clusters formed",
        elapsed,
        "intel_client",
    )

    return {
        "clusters": clusters,
        "stage": TAPStage.BUILD_PROFILES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "cluster_activity",
    }


async def build_profiles(
    state: ThreatActorProfilerState,
) -> dict[str, Any]:
    """Build threat actor profiles from clusters."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    profiles = await toolkit.build_profiles(state.clusters, state.indicators)

    try:
        ctx = _json.dumps(
            {
                "cluster_count": len(state.clusters),
                "profile_count": len(profiles),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_BUILD_PROFILES,
            user_prompt=f"Profile building context:\n{ctx}",
            schema=ProfileBuildOutput,
        )
        if hasattr(llm_result, "profiles_built"):
            logger.info("llm_enhanced", node="build_profiles")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="build_profiles",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "build_profiles",
        f"building from {len(state.clusters)} clusters",
        f"{len(profiles)} profiles built",
        elapsed,
        "intel_client",
    )
    await toolkit.record_metric("profiles_built", float(len(profiles)))

    return {
        "profiles": profiles,
        "stage": TAPStage.MAP_TTPS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "build_profiles",
    }


async def map_ttps(
    state: ThreatActorProfilerState,
) -> dict[str, Any]:
    """Map MITRE ATT&CK TTPs to actor profiles."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    mappings = await toolkit.map_ttps(state.profiles)
    tactics = {m.get("tactic") for m in mappings}

    try:
        ctx = _json.dumps(
            {
                "profile_count": len(state.profiles),
                "mapping_count": len(mappings),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_MAP_TTPS,
            user_prompt=f"TTP mapping context:\n{ctx}",
            schema=TTPMappingOutput,
        )
        if hasattr(llm_result, "techniques_mapped"):
            logger.info("llm_enhanced", node="map_ttps")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="map_ttps")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "map_ttps",
        f"mapping TTPs for {len(state.profiles)} profiles",
        f"{len(mappings)} mappings, {len(tactics)} tactics",
        elapsed,
        "mitre_client",
    )

    return {
        "ttp_mappings": mappings,
        "stage": TAPStage.ASSESS_TARGETING,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "map_ttps",
    }


async def assess_targeting(
    state: ThreatActorProfilerState,
) -> dict[str, Any]:
    """Assess targeting patterns for each actor."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments = await toolkit.assess_targeting(state.profiles, state.ttp_mappings)
    high_risk = sum(1 for a in assessments if a.get("risk_to_org", 0) > 0.7)

    try:
        ctx = _json.dumps(
            {
                "profile_count": len(state.profiles),
                "assessment_count": len(assessments),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ASSESS_TARGETING,
            user_prompt=f"Targeting assessment context:\n{ctx}",
            schema=TargetingOutput,
        )
        if hasattr(llm_result, "actors_assessed"):
            logger.info("llm_enhanced", node="assess_targeting")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_targeting",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "assess_targeting",
        f"assessing {len(state.profiles)} profiles",
        f"{len(assessments)} assessments, {high_risk} high-risk",
        elapsed,
        "intel_client",
    )

    return {
        "targeting_assessments": assessments,
        "stage": TAPStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_targeting",
    }


async def generate_report(
    state: ThreatActorProfilerState,
) -> dict[str, Any]:
    """Generate final threat actor profiling report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report = {
        "request_id": state.request_id,
        "indicators": len(state.indicators),
        "clusters": len(state.clusters),
        "profiles": len(state.profiles),
        "ttp_mappings": len(state.ttp_mappings),
        "targeting_assessments": len(state.targeting_assessments),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric("profiling_duration_ms", float(duration_ms))

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "generate_report",
        f"finalizing {state.request_id}",
        f"report complete in {duration_ms}ms",
        elapsed,
        None,
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
