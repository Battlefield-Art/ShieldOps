"""Node implementations for the Incident Triage Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import time
from typing import Any

import structlog

from shieldops.agents.incident_triage.models import (
    IncidentSeverity,
    IncidentTriageState,
    ReasoningStep,
    TriageStage,
)
from shieldops.agents.incident_triage.prompts import (
    SYSTEM_CLASSIFY,
    SYSTEM_ENRICH,
    SYSTEM_REPORT,
    SYSTEM_ROUTE,
    ClassificationOutput,
    EnrichmentOutput,
    ReportOutput,
    RoutingOutput,
)
from shieldops.agents.incident_triage.tools import IncidentTriageToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: IncidentTriageToolkit | None = None


def set_toolkit(toolkit: IncidentTriageToolkit) -> None:
    """Set the shared toolkit instance for all nodes."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> IncidentTriageToolkit:
    if _toolkit is None:
        return IncidentTriageToolkit()
    return _toolkit


async def ingest(state: IncidentTriageState) -> dict[str, Any]:
    """Validate and normalize incoming incidents."""
    start = time.time()
    incidents = state.incoming_incidents

    logger.info(
        "incident_triage.ingest",
        request_id=state.request_id,
        incident_count=len(incidents),
    )

    # Normalize: ensure IDs exist
    for i, inc in enumerate(incidents):
        if not inc.id:
            inc.id = f"inc-{state.request_id}-{i}"
        if inc.timestamp == 0.0:
            inc.timestamp = time.time()

    step = ReasoningStep(
        step="ingest",
        detail=f"Ingested {len(incidents)} incident(s)",
        confidence="high",
        metadata={"count": len(incidents)},
    )

    elapsed = int((time.time() - start) * 1000)
    return {
        "incoming_incidents": incidents,
        "stage": TriageStage.CLASSIFY,
        "current_step": "ingest",
        "reasoning_chain": [*state.reasoning_chain, step],
        "session_start": start if state.session_start == 0.0 else state.session_start,
        "stats": {**state.stats, "ingest_ms": elapsed, "raw_count": len(incidents)},
    }


async def classify(state: IncidentTriageState) -> dict[str, Any]:
    """Classify severity and category for each incident."""
    start = time.time()
    toolkit = _get_toolkit()
    incidents = state.incoming_incidents

    # Heuristic classification
    classifications = await toolkit.classify_severity(incidents)

    # LLM enhancement: refine classification with deeper reasoning
    for i, cls in enumerate(classifications):
        try:
            inc = incidents[i] if i < len(incidents) else None
            if inc is None:
                continue
            context = _json.dumps(
                {
                    "title": inc.title,
                    "description": inc.description,
                    "source": inc.source,
                    "raw_severity": inc.raw_severity,
                    "alerts": inc.alerts[:5],
                    "affected_services": inc.affected_services,
                    "heuristic_severity": cls.severity.value,
                    "heuristic_category": cls.category.value,
                },
                default=str,
            )
            llm_result = await llm_structured(
                system_prompt=SYSTEM_CLASSIFY,
                user_prompt=f"Classify this incident:\n{context}",
                schema=ClassificationOutput,
            )
            if hasattr(llm_result, "severity"):
                llm_sev = getattr(llm_result, "severity", "")
                if llm_sev in [s.value for s in IncidentSeverity]:
                    cls.severity = IncidentSeverity(llm_sev)
                llm_reasoning = getattr(llm_result, "reasoning", "")
                if llm_reasoning:
                    cls.reasoning = f"{cls.reasoning} | LLM: {llm_reasoning}"
            logger.info(
                "llm_enhanced",
                node="classify",
                incident_id=cls.incident_id,
                llm_severity=getattr(llm_result, "severity", "unknown"),
            )
        except Exception:
            logger.debug("llm_enhancement_skipped", node="classify", index=i)

    step = ReasoningStep(
        step="classify",
        detail=f"Classified {len(classifications)} incident(s)",
        confidence=(
            "high" if all(c.confidence != "uncertain" for c in classifications) else "medium"
        ),
        metadata={
            "severity_dist": {
                s.value: sum(1 for c in classifications if c.severity == s)
                for s in IncidentSeverity
            },
        },
    )

    elapsed = int((time.time() - start) * 1000)
    return {
        "classifications": classifications,
        "stage": TriageStage.ENRICH,
        "current_step": "classify",
        "reasoning_chain": [*state.reasoning_chain, step],
        "stats": {**state.stats, "classify_ms": elapsed},
    }


async def enrich(state: IncidentTriageState) -> dict[str, Any]:
    """Enrich incidents with context: customer impact, blast radius, related changes."""
    start = time.time()
    toolkit = _get_toolkit()

    enrichments = await toolkit.enrich_context(state.incoming_incidents)

    # LLM enhancement: deeper enrichment reasoning
    for i, enr in enumerate(enrichments):
        try:
            inc = state.incoming_incidents[i] if i < len(state.incoming_incidents) else None
            if inc is None:
                continue
            context = _json.dumps(
                {
                    "title": inc.title,
                    "description": inc.description,
                    "affected_services": inc.affected_services,
                    "current_blast_radius": enr.blast_radius,
                    "affected_customers": enr.affected_customers,
                },
                default=str,
            )
            llm_result = await llm_structured(
                system_prompt=SYSTEM_ENRICH,
                user_prompt=f"Enrich this incident context:\n{context}",
                schema=EnrichmentOutput,
            )
            if hasattr(llm_result, "blast_radius"):
                llm_blast = getattr(llm_result, "blast_radius", "")
                if llm_blast:
                    enr.blast_radius = llm_blast
                llm_runbook = getattr(llm_result, "recommended_runbook", "")
                if llm_runbook:
                    enr.runbook_url = llm_runbook
            logger.info("llm_enhanced", node="enrich", incident_id=enr.incident_id)
        except Exception:
            logger.debug("llm_enhancement_skipped", node="enrich", index=i)

    step = ReasoningStep(
        step="enrich",
        detail=f"Enriched {len(enrichments)} incident(s)",
        confidence="high",
        metadata={"enrichment_count": len(enrichments)},
    )

    elapsed = int((time.time() - start) * 1000)
    return {
        "enrichments": enrichments,
        "stage": TriageStage.DEDUPLICATE,
        "current_step": "enrich",
        "reasoning_chain": [*state.reasoning_chain, step],
        "stats": {**state.stats, "enrich_ms": elapsed},
    }


async def deduplicate(state: IncidentTriageState) -> dict[str, Any]:
    """Deduplicate incidents by merging related/duplicate entries."""
    start = time.time()
    toolkit = _get_toolkit()

    deduped, merged_count = await toolkit.deduplicate_incidents(state.incoming_incidents)

    step = ReasoningStep(
        step="deduplicate",
        detail=(
            f"Deduplicated: {len(state.incoming_incidents)} -> "
            f"{len(deduped)} ({merged_count} merged)"
        ),
        confidence="high",
        metadata={"merged": merged_count, "remaining": len(deduped)},
    )

    elapsed = int((time.time() - start) * 1000)
    return {
        "incoming_incidents": deduped,
        "deduplicated_count": merged_count,
        "stage": TriageStage.ROUTE,
        "current_step": "deduplicate",
        "reasoning_chain": [*state.reasoning_chain, step],
        "stats": {**state.stats, "dedup_ms": elapsed, "merged_count": merged_count},
    }


async def route(state: IncidentTriageState) -> dict[str, Any]:
    """Route incidents to the appropriate team based on classification and enrichment."""
    start = time.time()
    toolkit = _get_toolkit()

    routing_decisions = await toolkit.route_incidents(state.classifications, state.enrichments)

    # LLM enhancement: validate and refine routing
    for decision in routing_decisions:
        try:
            cls_match = next(
                (c for c in state.classifications if c.incident_id == decision.incident_id),
                None,
            )
            enr_match = next(
                (e for e in state.enrichments if e.incident_id == decision.incident_id),
                None,
            )
            context = _json.dumps(
                {
                    "incident_id": decision.incident_id,
                    "severity": cls_match.severity.value if cls_match else "unknown",
                    "category": cls_match.category.value if cls_match else "unknown",
                    "confidence": cls_match.confidence.value if cls_match else "unknown",
                    "blast_radius": enr_match.blast_radius if enr_match else "unknown",
                    "affected_customers": enr_match.affected_customers if enr_match else 0,
                    "current_team": decision.assigned_team,
                },
                default=str,
            )
            llm_result = await llm_structured(
                system_prompt=SYSTEM_ROUTE,
                user_prompt=f"Validate routing for incident:\n{context}",
                schema=RoutingOutput,
            )
            if hasattr(llm_result, "assigned_team"):
                llm_team = getattr(llm_result, "assigned_team", "")
                if llm_team:
                    decision.assigned_team = llm_team
                llm_esc = getattr(llm_result, "escalation_required", None)
                if llm_esc is not None:
                    decision.escalation_required = llm_esc
                llm_reason = getattr(llm_result, "routing_reasoning", "")
                if llm_reason:
                    decision.routing_reason = f"{decision.routing_reason} | LLM: {llm_reason}"
            logger.info(
                "llm_enhanced",
                node="route",
                incident_id=decision.incident_id,
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="route",
                incident_id=decision.incident_id,
            )

    escalated = sum(1 for d in routing_decisions if d.escalation_required)
    auto_rem = sum(1 for d in routing_decisions if d.auto_remediation_possible)

    step = ReasoningStep(
        step="route",
        detail=(
            f"Routed {len(routing_decisions)} incident(s): "
            f"{escalated} escalated, {auto_rem} auto-remediable"
        ),
        confidence="high",
        metadata={"escalated": escalated, "auto_remediation": auto_rem},
    )

    elapsed = int((time.time() - start) * 1000)
    return {
        "routing_decisions": routing_decisions,
        "stage": TriageStage.REPORT,
        "current_step": "route",
        "reasoning_chain": [*state.reasoning_chain, step],
        "stats": {
            **state.stats,
            "route_ms": elapsed,
            "escalated": escalated,
            "auto_remediation": auto_rem,
        },
    }


async def generate_report(state: IncidentTriageState) -> dict[str, Any]:
    """Generate a triage summary report with stats and recommendations."""
    start = time.time()
    total_elapsed = int((time.time() - state.session_start) * 1000)

    # Build stats summary
    sev_counts: dict[str, int] = {}
    for cls in state.classifications:
        sev_counts[cls.severity.value] = sev_counts.get(cls.severity.value, 0) + 1

    cat_counts: dict[str, int] = {}
    for cls in state.classifications:
        cat_counts[cls.category.value] = cat_counts.get(cls.category.value, 0) + 1

    team_counts: dict[str, int] = {}
    for rd in state.routing_decisions:
        team_counts[rd.assigned_team] = team_counts.get(rd.assigned_team, 0) + 1

    report_stats: dict[str, Any] = {
        "total_incidents": len(state.incoming_incidents),
        "deduplicated": state.deduplicated_count,
        "severity_distribution": sev_counts,
        "category_distribution": cat_counts,
        "team_distribution": team_counts,
        "escalations": sum(1 for d in state.routing_decisions if d.escalation_required),
        "auto_remediable": sum(1 for d in state.routing_decisions if d.auto_remediation_possible),
    }

    # LLM enhancement: generate executive summary
    executive_summary = ""
    try:
        context = _json.dumps(
            {
                "stats": report_stats,
                "classifications": [c.model_dump() for c in state.classifications],
                "routing": [r.model_dump() for r in state.routing_decisions],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate triage report from:\n{context}",
            schema=ReportOutput,
        )
        if hasattr(llm_result, "executive_summary"):
            executive_summary = getattr(llm_result, "executive_summary", "")
            report_stats["executive_summary"] = executive_summary
            report_stats["key_findings"] = getattr(llm_result, "key_findings", [])
            report_stats["recommended_actions"] = getattr(llm_result, "recommended_actions", [])
            report_stats["risk_assessment"] = getattr(llm_result, "risk_assessment", "")
        logger.info("llm_enhanced", node="generate_report")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="generate_report")

    step = ReasoningStep(
        step="report",
        detail=f"Generated triage report: {len(state.incoming_incidents)} incidents processed",
        confidence="high",
        metadata=report_stats,
    )

    elapsed = int((time.time() - start) * 1000)
    return {
        "stage": TriageStage.REPORT,
        "current_step": "report",
        "stats": {**state.stats, **report_stats, "report_ms": elapsed},
        "reasoning_chain": [*state.reasoning_chain, step],
        "session_duration_ms": total_elapsed,
    }
