"""Node implementations for the Attack Narrative Builder Agent."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.attack_narrative_builder.models import (
    ANBStage,
    AttackNarrativeBuilderState,
    ReasoningStep,
)
from shieldops.agents.attack_narrative_builder.prompts import (
    SYSTEM_BUILD_TIMELINE,
    SYSTEM_CLUSTER_EVENTS,
    SYSTEM_GENERATE_NARRATIVE,
    SYSTEM_MAP_MITRE,
    SYSTEM_NARRATIVE_REPORT,
    EventClusterOutput,
    MITREMappingOutput,
    NarrativeOutput,
    NarrativeReportOutput,
    TimelineOutput,
)
from shieldops.agents.attack_narrative_builder.tools import (
    AttackNarrativeBuilderToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AttackNarrativeBuilderToolkit | None = None


def set_toolkit(toolkit: AttackNarrativeBuilderToolkit) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> AttackNarrativeBuilderToolkit:
    if _toolkit is None:
        return AttackNarrativeBuilderToolkit()
    return _toolkit


def _step(
    state: AttackNarrativeBuilderState,
    action: str,
    input_summary: str,
    output_summary: str,
    duration_ms: int,
    tool_used: str | None = None,
) -> ReasoningStep:
    return ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=duration_ms,
        tool_used=tool_used,
    )


async def collect_events(
    state: AttackNarrativeBuilderState,
) -> dict[str, Any]:
    """Collect security events from all sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    events = await toolkit.collect_events(state.config)

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "collect_events",
        f"config={list(state.config.keys())}",
        f"collected {len(events)} events",
        elapsed,
        "siem_client",
    )
    await toolkit.record_metric("events_collected", float(len(events)))

    return {
        "events": events,
        "stage": ANBStage.CLUSTER,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_events",
        "session_start": start,
    }


async def cluster_events(
    state: AttackNarrativeBuilderState,
) -> dict[str, Any]:
    """Cluster related events together."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    clusters = await toolkit.cluster_events(state.events)

    try:
        ctx = _json.dumps(
            {"event_count": len(state.events), "cluster_count": len(clusters)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CLUSTER_EVENTS,
            user_prompt=f"Event clustering context:\n{ctx}",
            schema=EventClusterOutput,
        )
        if hasattr(llm_result, "clusters"):
            logger.info("llm_enhanced", node="cluster_events")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="cluster_events")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "cluster_events",
        f"{len(state.events)} events",
        f"{len(clusters)} clusters",
        elapsed,
        "clustering_engine",
    )

    return {
        "clusters": clusters,
        "stage": ANBStage.TIMELINE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "cluster_events",
    }


async def build_timeline(
    state: AttackNarrativeBuilderState,
) -> dict[str, Any]:
    """Build chronological attack timeline."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    timeline = await toolkit.build_timeline(state.events, state.clusters)

    try:
        ctx = _json.dumps(
            {"events": len(state.events), "clusters": len(state.clusters)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_BUILD_TIMELINE,
            user_prompt=f"Timeline construction context:\n{ctx}",
            schema=TimelineOutput,
        )
        if hasattr(llm_result, "timeline_entries"):
            logger.info("llm_enhanced", node="build_timeline")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="build_timeline")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "build_timeline",
        f"{len(state.events)} events, {len(state.clusters)} clusters",
        f"{len(timeline)} timeline entries",
        elapsed,
        "timeline_engine",
    )

    return {
        "timeline": timeline,
        "stage": ANBStage.NARRATE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "build_timeline",
    }


async def generate_narrative(
    state: AttackNarrativeBuilderState,
) -> dict[str, Any]:
    """Generate human-readable narrative segments."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    segments = await toolkit.generate_narrative(state.timeline, state.clusters)

    try:
        ctx = _json.dumps(
            {"timeline_entries": len(state.timeline), "clusters": len(state.clusters)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_GENERATE_NARRATIVE,
            user_prompt=f"Narrative generation context:\n{ctx}",
            schema=NarrativeOutput,
        )
        if hasattr(llm_result, "title"):
            logger.info("llm_enhanced", node="generate_narrative")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="generate_narrative")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "generate_narrative",
        f"{len(state.timeline)} timeline entries",
        f"{len(segments)} narrative segments",
        elapsed,
        "narrative_engine",
    )

    return {
        "narrative_segments": segments,
        "stage": ANBStage.MITRE_MAP,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "generate_narrative",
    }


async def map_mitre(
    state: AttackNarrativeBuilderState,
) -> dict[str, Any]:
    """Map attack to MITRE ATT&CK techniques."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    mappings = await toolkit.map_mitre(state.clusters, state.narrative_segments)

    try:
        ctx = _json.dumps(
            {
                "clusters": len(state.clusters),
                "segments": len(state.narrative_segments),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_MAP_MITRE,
            user_prompt=f"MITRE mapping context:\n{ctx}",
            schema=MITREMappingOutput,
        )
        if hasattr(llm_result, "mappings"):
            logger.info("llm_enhanced", node="map_mitre")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="map_mitre")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "map_mitre",
        f"{len(state.clusters)} clusters, {len(state.narrative_segments)} segments",
        f"{len(mappings)} MITRE mappings",
        elapsed,
        "mitre_mapper",
    )

    return {
        "mitre_mappings": mappings,
        "stage": ANBStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "map_mitre",
    }


async def generate_report(
    state: AttackNarrativeBuilderState,
) -> dict[str, Any]:
    """Generate final narrative report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report = {
        "request_id": state.request_id,
        "events_processed": len(state.events),
        "clusters_analyzed": len(state.clusters),
        "timeline_entries": len(state.timeline),
        "narrative_segments": len(state.narrative_segments),
        "mitre_techniques_mapped": len(state.mitre_mappings),
        "duration_ms": duration_ms,
    }

    try:
        ctx = _json.dumps(report, default=str)
        llm_result = await llm_structured(
            system_prompt=SYSTEM_NARRATIVE_REPORT,
            user_prompt=f"Narrative report context:\n{ctx}",
            schema=NarrativeReportOutput,
        )
        if hasattr(llm_result, "quality_score"):
            report["quality_score"] = llm_result.quality_score
            logger.info("llm_enhanced", node="generate_report")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="generate_report")

    await toolkit.record_metric("narrative_duration_ms", float(duration_ms))

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
