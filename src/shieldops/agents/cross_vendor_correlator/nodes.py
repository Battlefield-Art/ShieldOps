"""Node implementations for the Cross-Vendor Correlator Agent."""

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.cross_vendor_correlator.models import (
    CorrelationStage,
    ReasoningStep,
)
from shieldops.agents.cross_vendor_correlator.prompts import (
    SYSTEM_CORRELATE,
    SYSTEM_KILL_CHAIN,
    SYSTEM_REPORT,
    SYSTEM_SITUATION,
    CorrelationReportOutput,
    EntityCorrelationOutput,
    KillChainOutput,
    SituationOutput,
)
from shieldops.agents.cross_vendor_correlator.tools import (
    CrossVendorCorrelatorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: CrossVendorCorrelatorToolkit | None = None


def set_toolkit(
    toolkit: CrossVendorCorrelatorToolkit,
) -> None:
    """Set the global toolkit instance."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> CrossVendorCorrelatorToolkit:
    if _toolkit is None:
        return CrossVendorCorrelatorToolkit()
    return _toolkit


async def ingest_vendor_alerts(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Ingest alerts from configured vendors."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    alerts = await toolkit.ingest_from_vendor(
        tenant_id=state.get("tenant_id", ""),
        vendors=state.get("vendors", []),
        time_window_minutes=state.get("time_window_minutes", 60),
    )

    step = ReasoningStep(
        step_number=len(state.get("reasoning_chain", [])) + 1,
        action="ingest_vendor_alerts",
        input_summary=(f"vendors={state.get('vendors', [])}"),
        output_summary=(f"Ingested {len(alerts)} alerts"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="ingest_from_vendor",
    )

    return {
        "vendor_alerts": alerts,
        "total_alerts_ingested": len(alerts),
        "current_stage": (CorrelationStage.INGEST_VENDOR_ALERTS),
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            step,
        ],
    }


async def normalize_to_ocsf(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Normalize vendor alerts to OCSF schema."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    events = await toolkit.normalize_to_ocsf(
        state.get("vendor_alerts", []),
    )

    step = ReasoningStep(
        step_number=len(state.get("reasoning_chain", [])) + 1,
        action="normalize_to_ocsf",
        input_summary=(f"{len(state.get('vendor_alerts', []))} vendor alerts"),
        output_summary=(f"Normalized {len(events)} OCSF events"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="normalize_to_ocsf",
    )

    return {
        "ocsf_events": events,
        "current_stage": (CorrelationStage.NORMALIZE_TO_OCSF),
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            step,
        ],
    }


async def correlate_by_entity(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Correlate OCSF events by shared entities."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    correlations = await toolkit.correlate_by_entity(
        state.get("ocsf_events", []),
    )

    # LLM enrichment for each correlation
    for corr in correlations:
        try:
            result = await llm_structured(
                system_prompt=SYSTEM_CORRELATE,
                user_prompt=(
                    f"Entity: {corr.entity}\n"
                    f"Vendors: "
                    f"{', '.join(corr.vendors_involved)}"
                    f"\nEvents: {len(corr.event_ids)}"
                    f"\nTime span: "
                    f"{corr.time_span_seconds}s"
                ),
                output_schema=(EntityCorrelationOutput),
            )
            corr.entity_type = result.entity_type
        except Exception:
            logger.warning(
                "cross_vendor.llm_correlate_fallback",
                entity=corr.entity,
            )

    vendors_seen = set()
    for corr in correlations:
        vendors_seen.update(corr.vendors_involved)

    step = ReasoningStep(
        step_number=len(state.get("reasoning_chain", [])) + 1,
        action="correlate_by_entity",
        input_summary=(f"{len(state.get('ocsf_events', []))} OCSF events"),
        output_summary=(f"Found {len(correlations)} correlations"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="correlate_by_entity",
    )

    return {
        "correlations": correlations,
        "vendors_correlated": len(vendors_seen),
        "current_stage": (CorrelationStage.CORRELATE_BY_ENTITY),
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            step,
        ],
    }


async def build_kill_chain(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Map correlations to MITRE ATT&CK kill chain."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    mappings = await toolkit.map_kill_chain(
        correlations=state.get("correlations", []),
        events=state.get("ocsf_events", []),
    )

    # LLM enrichment for kill chain
    for mapping in mappings:
        try:
            result = await llm_structured(
                system_prompt=SYSTEM_KILL_CHAIN,
                user_prompt=(
                    f"Tactic: {mapping.tactic}\n"
                    f"Events: "
                    f"{len(mapping.events_mapped)}\n"
                    f"Score: "
                    f"{mapping.progression_score}"
                ),
                output_schema=KillChainOutput,
            )
            mapping.tactic = result.tactic
            mapping.technique_id = result.technique_id
            mapping.technique_name = result.technique_name
        except Exception:
            logger.warning(
                "cross_vendor.llm_killchain_fallback",
                mapping_id=mapping.id,
            )

    step = ReasoningStep(
        step_number=len(state.get("reasoning_chain", [])) + 1,
        action="build_kill_chain",
        input_summary=(f"{len(state.get('correlations', []))} correlations"),
        output_summary=(f"Mapped {len(mappings)} kill chain stages"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="map_kill_chain",
    )

    return {
        "kill_chain_mappings": mappings,
        "current_stage": (CorrelationStage.BUILD_KILL_CHAIN),
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            step,
        ],
    }


async def create_situations(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Create unified situations from correlations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    situations = await toolkit.create_situation(
        correlations=state.get("correlations", []),
        kill_chain_mappings=state.get("kill_chain_mappings", []),
    )

    # LLM enrichment for situations
    for sit in situations:
        try:
            result = await llm_structured(
                system_prompt=SYSTEM_SITUATION,
                user_prompt=(
                    f"Title: {sit.title}\n"
                    f"Severity: {sit.severity}\n"
                    f"Vendors: {sit.vendor_count}\n"
                    f"Events: {sit.event_count}\n"
                    f"Kill chain: "
                    f"{', '.join(sit.kill_chain_stages)}"
                ),
                output_schema=SituationOutput,
            )
            sit.title = result.title
            sit.narrative = result.narrative
            sit.recommended_actions = result.recommended_actions
        except Exception:
            logger.warning(
                "cross_vendor.llm_situation_fallback",
                situation_id=sit.id,
            )

    step = ReasoningStep(
        step_number=len(state.get("reasoning_chain", [])) + 1,
        action="create_situations",
        input_summary=(f"{len(state.get('correlations', []))} correlations"),
        output_summary=(f"Created {len(situations)} situations"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="create_situation",
    )

    return {
        "situations": situations,
        "total_situations_created": len(situations),
        "current_stage": (CorrelationStage.CREATE_SITUATIONS),
        "reasoning_chain": [
            *state.get("reasoning_chain", []),
            step,
        ],
    }


async def generate_report(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Generate the final correlation report."""
    start = datetime.now(UTC)

    situations = state.get("situations", [])
    try:
        result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(
                f"Alerts: "
                f"{state.get('total_alerts_ingested', 0)}"
                f"\nCorrelations: "
                f"{len(state.get('correlations', []))}"
                f"\nSituations: {len(situations)}"
                f"\nVendors: "
                f"{state.get('vendors_correlated', 0)}"
            ),
            output_schema=CorrelationReportOutput,
        )
        _ = result.executive_summary
    except Exception:
        logger.warning("cross_vendor.llm_report_fallback")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)

    step = ReasoningStep(
        step_number=len(state.get("reasoning_chain", [])) + 1,
        action="generate_report",
        input_summary=(f"{len(situations)} situations"),
        output_summary="Report generated",
        duration_ms=elapsed,
        tool_used="llm_structured",
    )

    chain = state.get("reasoning_chain", [])
    total_ms = (
        sum(s.duration_ms if hasattr(s, "duration_ms") else s.get("duration_ms", 0) for s in chain)
        + elapsed
    )

    return {
        "current_stage": CorrelationStage.REPORT,
        "reasoning_chain": [*chain, step],
        "session_duration_ms": total_ms,
    }
