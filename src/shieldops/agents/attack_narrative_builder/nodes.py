"""Attack Narrative Builder Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    ANBStage,
    AttackChainLink,
    ReasoningStep,
    SecurityEvent,
    TechniqueMapping,
    TimelineEntry,
)
from .tools import AttackNarrativeBuilderToolkit

logger = structlog.get_logger()

_toolkit: AttackNarrativeBuilderToolkit | None = None  # noqa: PLW0603


def set_toolkit(tk: AttackNarrativeBuilderToolkit) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = tk


def _get_toolkit() -> AttackNarrativeBuilderToolkit:
    assert _toolkit is not None, "Toolkit not initialised"
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Collect Events
# ------------------------------------------------------------------


async def collect_events(
    state: dict[str, Any],
    toolkit: AttackNarrativeBuilderToolkit,
) -> dict[str, Any]:
    """Collect security events from multiple sources."""
    logger.info("anb.node.collect_events")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    events = await toolkit.collect_events(tenant_id)
    data = [e.model_dump() for e in events]

    note = f"Collected {len(events)} security events"

    return {
        "stage": ANBStage.CORRELATE_TIMELINE.value,
        "security_events": data,
        "total_events_collected": len(events),
        "current_step": "collect_events",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="collect_events",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Correlate Timeline
# ------------------------------------------------------------------


async def correlate_timeline(
    state: dict[str, Any],
    toolkit: AttackNarrativeBuilderToolkit,
) -> dict[str, Any]:
    """Correlate events into a timeline."""
    logger.info("anb.node.correlate_timeline")
    state = _to_dict(state)

    events = [SecurityEvent(**e) for e in state.get("security_events", [])]
    timeline = await toolkit.correlate_timeline(events)
    data = [t.model_dump() for t in timeline]

    note = f"Correlated {len(timeline)} timeline entries from {len(events)} events"

    try:
        from .prompts import SYSTEM_ANALYZE, TimelineInsight

        ctx = json.dumps(
            {
                "entries": [
                    {
                        "timestamp": t.timestamp,
                        "host": t.host,
                        "user": t.user,
                        "severity": t.severity.value,
                        "description": t.description,
                    }
                    for t in timeline[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            TimelineInsight,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"Attack timeline:\n{ctx}",
                schema=TimelineInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="anb",
            node="correlate_timeline",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="anb",
            node="correlate_timeline",
        )

    return {
        "stage": ANBStage.RECONSTRUCT_CHAIN.value,
        "timeline_entries": data,
        "current_step": "correlate_timeline",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="correlate_timeline",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Reconstruct Chain
# ------------------------------------------------------------------


async def reconstruct_chain(
    state: dict[str, Any],
    toolkit: AttackNarrativeBuilderToolkit,
) -> dict[str, Any]:
    """Reconstruct the attack kill chain."""
    logger.info("anb.node.reconstruct_chain")
    state = _to_dict(state)

    timeline = [TimelineEntry(**t) for t in state.get("timeline_entries", [])]
    events = [SecurityEvent(**e) for e in state.get("security_events", [])]
    chain = await toolkit.reconstruct_chain(timeline, events)
    data = [c.model_dump() for c in chain]

    phases = len({c.phase for c in chain})
    note = f"Reconstructed {len(chain)} chain links across {phases} phases"

    return {
        "stage": ANBStage.MAP_TECHNIQUES.value,
        "attack_chain": data,
        "attack_phases_identified": phases,
        "current_step": "reconstruct_chain",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="reconstruct_chain",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Map Techniques
# ------------------------------------------------------------------


async def map_techniques(
    state: dict[str, Any],
    toolkit: AttackNarrativeBuilderToolkit,
) -> dict[str, Any]:
    """Map attack chain to MITRE ATT&CK techniques."""
    logger.info("anb.node.map_techniques")
    state = _to_dict(state)

    chain = [AttackChainLink(**c) for c in state.get("attack_chain", [])]
    events = [SecurityEvent(**e) for e in state.get("security_events", [])]
    mappings = await toolkit.map_techniques(chain, events)
    data = [m.model_dump() for m in mappings]

    note = f"Mapped {len(mappings)} MITRE ATT&CK techniques"

    return {
        "stage": ANBStage.BUILD_NARRATIVE.value,
        "technique_mappings": data,
        "current_step": "map_techniques",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="map_techniques",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Build Narrative
# ------------------------------------------------------------------


async def build_narrative(
    state: dict[str, Any],
    toolkit: AttackNarrativeBuilderToolkit,
) -> dict[str, Any]:
    """Build the attack narrative from chain and mappings."""
    logger.info("anb.node.build_narrative")
    state = _to_dict(state)

    chain = [AttackChainLink(**c) for c in state.get("attack_chain", [])]
    mappings = [TechniqueMapping(**m) for m in state.get("technique_mappings", [])]
    sections = await toolkit.build_narrative(chain, mappings)
    data = [s.model_dump() for s in sections]

    note = f"Built narrative with {len(sections)} sections"

    return {
        "stage": ANBStage.REPORT.value,
        "narrative_sections": data,
        "current_step": "build_narrative",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="build_narrative",
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
    toolkit: AttackNarrativeBuilderToolkit,
) -> dict[str, Any]:
    """Compile the final attack narrative report."""
    logger.info("anb.node.report")
    state = _to_dict(state)

    total_events = state.get("total_events_collected", 0)
    phases = state.get("attack_phases_identified", 0)
    chain_count = len(state.get("attack_chain", []))
    technique_count = len(state.get("technique_mappings", []))

    lines = [
        "# Attack Narrative Report",
        "",
        f"**Events collected:** {total_events}",
        f"**Attack phases:** {phases}",
        f"**Chain links:** {chain_count}",
        f"**MITRE techniques:** {technique_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "total_events": total_events,
                "phases": phases,
                "chain_links": chain_count,
                "techniques": technique_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=(f"Attack narrative:\n{ctx}"),
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="anb",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="anb",
            node="report",
        )

    return {
        "stage": ANBStage.REPORT.value,
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
