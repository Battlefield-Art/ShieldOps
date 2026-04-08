"""Node implementations for the Regulatory Change
Monitor Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.regulatory_change_monitor.models import (
    RCMStage,
    ReasoningStep,
    RegulatoryChangeMonitorState,
)
from shieldops.agents.regulatory_change_monitor.prompts import (
    SYSTEM_CONTROLS,
    SYSTEM_IMPACT,
    SYSTEM_PARSE,
    SYSTEM_REPORT,
    ChangeParseOutput,
    ControlMappingOutput,
    ImpactAssessmentOutput,
    RegulatoryReportOutput,
)
from shieldops.agents.regulatory_change_monitor.tools import (
    RegulatoryChangeMonitorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: RegulatoryChangeMonitorToolkit | None = None


def _get_toolkit() -> RegulatoryChangeMonitorToolkit:
    if _toolkit is None:
        return RegulatoryChangeMonitorToolkit()
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
# Node: monitor_sources
# ------------------------------------------------------------------


async def monitor_sources(
    state: RegulatoryChangeMonitorState,
) -> dict[str, Any]:
    """Monitor regulatory sources for new changes and
    updates."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    frameworks = [f.value for f in state.frameworks]
    changes = await toolkit.monitor_sources(
        sources=state.sources,
        frameworks=frameworks,
    )

    step = _step(
        state.reasoning_chain,
        "monitor_sources",
        (f"Monitoring {len(state.sources)} sources for {len(frameworks)} frameworks"),
        f"Found {len(changes)} raw changes",
        start,
        "feed_client",
    )

    return {
        "changes": changes,
        "stage": RCMStage.MONITOR_SOURCES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "monitor_sources",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: parse_changes
# ------------------------------------------------------------------


async def parse_changes(
    state: RegulatoryChangeMonitorState,
) -> dict[str, Any]:
    """Parse raw regulatory updates into structured
    change records."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    parsed = await toolkit.parse_changes(
        raw_changes=state.changes,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "change_count": len(state.changes),
                "changes_sample": state.changes[:5],
                "frameworks": [f.value for f in state.frameworks],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_PARSE,
            user_prompt=f"Parse regulatory changes:\n{ctx}",
            schema=ChangeParseOutput,
        )
        if llm_out.changes:  # type: ignore[union-attr]
            parsed = [
                *parsed,
                *llm_out.changes,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="parse_changes",
            count=len(llm_out.changes),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="parse_changes",
        )

    step = _step(
        state.reasoning_chain,
        "parse_changes",
        f"Parsing {len(state.changes)} raw changes",
        f"Produced {len(parsed)} parsed changes",
        start,
        "parser",
    )

    return {
        "parsed_changes": parsed,
        "total_changes": len(parsed),
        "stage": RCMStage.PARSE_CHANGES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "parse_changes",
    }


# ------------------------------------------------------------------
# Node: assess_impact
# ------------------------------------------------------------------


async def assess_impact(
    state: RegulatoryChangeMonitorState,
) -> dict[str, Any]:
    """Assess impact of parsed regulatory changes on
    the organization."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    impacts = await toolkit.assess_impact(
        changes=state.parsed_changes,
        scope=state.scope,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "changes": state.parsed_changes[:5],
                "scope": state.scope,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_IMPACT,
            user_prompt=f"Assess impact:\n{ctx}",
            schema=ImpactAssessmentOutput,
        )
        if llm_out.affected_controls:  # type: ignore[union-attr]
            impacts.append(
                {
                    "assessment_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "impact_level": llm_out.impact_level,  # type: ignore[union-attr]
                    "affected_controls": (llm_out.affected_controls),  # type: ignore[union-attr]
                    "compliance_gap": (llm_out.compliance_gap),  # type: ignore[union-attr]
                    "estimated_effort_hours": (llm_out.estimated_effort_hours),  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="assess_impact",
            controls=len(llm_out.affected_controls),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_impact",
        )

    _critical = sum(1 for i in impacts if i.get("impact_level") == "critical")
    _gaps = sum(1 for i in impacts if i.get("compliance_gap"))

    step = _step(
        state.reasoning_chain,
        "assess_impact",
        (f"Assessing {len(state.parsed_changes)} changes"),
        (f"Produced {len(impacts)} assessments, {_critical} critical"),
        start,
        "impact_assessor",
    )

    return {
        "impact_assessments": impacts,
        "critical_changes": _critical,
        "compliance_gaps": _gaps,
        "stage": RCMStage.ASSESS_IMPACT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_impact",
    }


# ------------------------------------------------------------------
# Node: map_controls
# ------------------------------------------------------------------


async def map_controls(
    state: RegulatoryChangeMonitorState,
) -> dict[str, Any]:
    """Map regulatory changes to internal security
    controls and identify gaps."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    mappings = await toolkit.map_to_controls(
        changes=state.parsed_changes,
        impacts=state.impact_assessments,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "changes": state.parsed_changes[:5],
                "impacts": state.impact_assessments[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_CONTROLS,
            user_prompt=f"Map to controls:\n{ctx}",
            schema=ControlMappingOutput,
        )
        if llm_out.mappings:  # type: ignore[union-attr]
            mappings = [
                *mappings,
                *llm_out.mappings,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="map_controls",
            gaps=llm_out.gaps_found,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="map_controls",
        )

    step = _step(
        state.reasoning_chain,
        "map_controls",
        (f"Mapping {len(state.parsed_changes)} changes to controls"),
        f"Produced {len(mappings)} control mappings",
        start,
        "control_mapper",
    )

    return {
        "control_mappings": mappings,
        "stage": RCMStage.MAP_CONTROLS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "map_controls",
    }


# ------------------------------------------------------------------
# Node: generate_actions
# ------------------------------------------------------------------


async def generate_actions(
    state: RegulatoryChangeMonitorState,
) -> dict[str, Any]:
    """Generate prioritized action items from regulatory
    change analysis."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    actions = await toolkit.generate_actions(
        changes=state.parsed_changes,
        impacts=state.impact_assessments,
        mappings=state.control_mappings,
    )

    step = _step(
        state.reasoning_chain,
        "generate_actions",
        (f"Generating actions from {len(state.control_mappings)} mappings"),
        f"Generated {len(actions)} action items",
        start,
        "action_generator",
    )

    return {
        "action_items": actions,
        "actions_generated": len(actions),
        "stage": RCMStage.GENERATE_ACTIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "generate_actions",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: RegulatoryChangeMonitorState,
) -> dict[str, Any]:
    """Generate the final regulatory change monitoring
    report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {
        "scan_name": state.scan_name,
        "total_changes": state.total_changes,
        "critical_changes": state.critical_changes,
        "compliance_gaps": state.compliance_gaps,
        "actions_generated": state.actions_generated,
    }

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "scan_name": state.scan_name,
                "total_changes": state.total_changes,
                "critical_changes": state.critical_changes,
                "compliance_gaps": state.compliance_gaps,
                "parsed_changes_sample": state.parsed_changes[:5],
                "impact_sample": state.impact_assessments[:5],
                "action_items": state.action_items[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate regulatory report:\n{ctx}"),
            schema=RegulatoryReportOutput,
        )
        if isinstance(llm_out, RegulatoryReportOutput):
            report.update(
                {
                    "executive_summary": (llm_out.executive_summary),
                    "critical_changes_detail": (llm_out.critical_changes),
                    "action_items_detail": llm_out.action_items,
                    "compliance_posture": (llm_out.compliance_posture),
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                actions=len(llm_out.action_items),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    # Record metrics
    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    await toolkit.record_metric(
        scan_id=state.request_id,
        outcome={
            "total_changes": state.total_changes,
            "critical_changes": state.critical_changes,
            "compliance_gaps": state.compliance_gaps,
            "actions_generated": state.actions_generated,
            "duration_ms": duration_ms,
        },
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        (f"Reporting on {state.total_changes} changes"),
        (f"Report generated, {state.compliance_gaps} gaps found"),
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": RCMStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
