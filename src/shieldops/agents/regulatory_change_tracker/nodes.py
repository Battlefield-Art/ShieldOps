"""Regulatory Change Tracker Agent — Node implementations."""

from __future__ import annotations

from typing import Any

import structlog
from pydantic import BaseModel, Field

from shieldops.utils.llm import llm_structured

from .models import RCTStage
from .tools import RegulatoryChangeTrackerToolkit

logger = structlog.get_logger()

_toolkit: RegulatoryChangeTrackerToolkit | None = None


def set_toolkit(
    toolkit: RegulatoryChangeTrackerToolkit,
) -> None:
    """Configure the module-level toolkit."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> RegulatoryChangeTrackerToolkit:
    if _toolkit is None:
        return RegulatoryChangeTrackerToolkit()
    return _toolkit


class _LLMImpactAssessment(BaseModel):
    """LLM-generated impact assessment."""

    critical_changes: list[str] = Field(
        description="Most critical regulatory changes",
    )
    compliance_gaps: list[str] = Field(
        description="Identified compliance gaps",
    )
    risk_summary: str = Field(
        description="Overall regulatory risk summary",
    )


async def scan_sources(
    state: dict[str, Any],
    toolkit: RegulatoryChangeTrackerToolkit,
) -> dict[str, Any]:
    """Scan regulatory sources for updates."""
    logger.info("rct.node.scan_sources")

    regulations = state.get(
        "regulations",
        [
            "gdpr",
            "ccpa",
            "hipaa",
            "pci_dss",
            "sox",
            "nist",
        ],
    )
    updates = await toolkit.scan_sources(regulations)

    return {
        "stage": RCTStage.PARSE_UPDATES.value,
        "updates": updates,
        "sources_scanned": len(regulations),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Scanned {len(regulations)} sources, found {len(updates)} updates"],
    }


async def parse_updates(
    state: dict[str, Any],
    toolkit: RegulatoryChangeTrackerToolkit,
) -> dict[str, Any]:
    """Parse and normalize regulatory updates."""
    logger.info("rct.node.parse_updates")
    updates = state.get("updates", [])

    critical = sum(1 for u in updates if u.get("impact") == "critical")

    return {
        "stage": RCTStage.ASSESS_IMPACT.value,
        "critical_changes": critical,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Parsed {len(updates)} updates, {critical} critical"],
    }


async def assess_impact(
    state: dict[str, Any],
    toolkit: RegulatoryChangeTrackerToolkit,
) -> dict[str, Any]:
    """Assess impact of regulatory changes."""
    logger.info("rct.node.assess_impact")
    updates = state.get("updates", [])

    llm_note = ""
    try:
        summary = "\n".join(f"- {u.get('title', '')} [{u.get('impact')}]" for u in updates[:20])
        result = await llm_structured(
            system_prompt=(
                "You are a regulatory compliance analyst. "
                "Assess the impact of regulatory changes "
                "on enterprise security controls."
            ),
            user_prompt=(f"Regulatory updates:\n{summary}"),
            schema=_LLMImpactAssessment,
        )
        if isinstance(result, _LLMImpactAssessment):
            llm_note = f" LLM: {result.risk_summary} ({len(result.critical_changes)} critical)"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="rct",
            node="assess_impact",
        )

    note = f"Impact assessed for {len(updates)} updates"
    return {
        "stage": RCTStage.MAP_CONTROLS.value,
        "reasoning_chain": state.get("reasoning_chain", []) + [note + llm_note],
    }


async def map_controls(
    state: dict[str, Any],
    toolkit: RegulatoryChangeTrackerToolkit,
) -> dict[str, Any]:
    """Map regulatory changes to internal controls."""
    logger.info("rct.node.map_controls")
    updates = state.get("updates", [])

    all_mappings: list[dict[str, Any]] = []
    for update in updates:
        mappings = await toolkit.map_controls(update)
        all_mappings.extend(mappings)

    controls_affected = len({m.get("control_id") for m in all_mappings})

    return {
        "stage": RCTStage.NOTIFY_STAKEHOLDERS.value,
        "control_mappings": all_mappings,
        "controls_affected": controls_affected,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Mapped {len(all_mappings)} control impacts across {controls_affected} controls"],
    }


async def notify_stakeholders(
    state: dict[str, Any],
    toolkit: RegulatoryChangeTrackerToolkit,
) -> dict[str, Any]:
    """Notify stakeholders about regulatory changes."""
    logger.info("rct.node.notify_stakeholders")
    updates = state.get("updates", [])

    critical_updates = [u for u in updates if u.get("impact") in ("critical", "high")]

    all_notifications: list[dict[str, Any]] = []
    for update in critical_updates:
        notifs = await toolkit.notify_stakeholders(update)
        all_notifications.extend(notifs)

    return {
        "stage": RCTStage.REPORT.value,
        "notifications": all_notifications,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Sent {len(all_notifications)} notifications "
            f"for {len(critical_updates)} critical updates"
        ],
    }


async def report(
    state: dict[str, Any],
    toolkit: RegulatoryChangeTrackerToolkit,
) -> dict[str, Any]:
    """Generate final regulatory change report."""
    logger.info("rct.node.report")

    rpt = toolkit.generate_report(
        updates=state.get("updates", []),
        mappings=state.get("control_mappings", []),
        notifications=state.get("notifications", []),
    )

    return {
        "stage": RCTStage.REPORT.value,
        "report": rpt,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Report generated: {rpt.get('total_updates')} "
            f"updates, {rpt.get('controls_affected')} "
            f"controls affected"
        ],
    }
