"""Node implementations for the AI Triage Accelerator LangGraph workflow."""

from __future__ import annotations

import json as _json
import time
from typing import Any

import structlog

from shieldops.agents.ai_triage_accelerator.models import (
    AITriageAcceleratorState,
    Classification,
    ReasoningStep,
    RoutingDecision,
    TriageStage,
)
from shieldops.agents.ai_triage_accelerator.prompts import (
    SYSTEM_CLASSIFY,
    SYSTEM_CONFIDENCE,
    SYSTEM_ENRICH,
    SYSTEM_REPORT,
    SYSTEM_ROUTE,
    ClassifyOutput,
    ConfidenceOutput,
    EnrichOutput,
    ReportOutput,
    RouteOutput,
)
from shieldops.agents.ai_triage_accelerator.tools import (
    AITriageAcceleratorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AITriageAcceleratorToolkit | None = None


def set_toolkit(
    toolkit: AITriageAcceleratorToolkit,
) -> None:
    """Set the shared toolkit instance for all nodes."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> AITriageAcceleratorToolkit:
    if _toolkit is None:
        return AITriageAcceleratorToolkit()
    return _toolkit


async def batch_ingest(
    state: AITriageAcceleratorState,
) -> dict[str, Any]:
    """Validate, normalize, and batch incoming alerts."""
    start = time.time()
    batch = state.alert_batch
    alerts = batch.alerts

    logger.info(
        "ai_triage.batch_ingest",
        request_id=state.request_id,
        alert_count=len(alerts),
    )

    # Normalize: ensure IDs exist
    for i, alert in enumerate(alerts):
        if not alert.get("id"):
            alert["id"] = f"alert-{state.request_id}-{i}"
        if not alert.get("timestamp"):
            alert["timestamp"] = time.time()

    batch.batch_size = len(alerts)
    batch.ingested_at = time.time()

    step = ReasoningStep(
        step="batch_ingest",
        detail=f"Ingested {len(alerts)} alert(s)",
        confidence="high",
        metadata={"count": len(alerts)},
    )

    elapsed = int((time.time() - start) * 1000)
    return {
        "alert_batch": batch,
        "batch_size": len(alerts),
        "stage": TriageStage.PARALLEL_CLASSIFY,
        "current_step": "batch_ingest",
        "reasoning_chain": [*state.reasoning_chain, step],
        "session_start": (start if state.session_start == 0.0 else state.session_start),
        "stats": {
            **state.stats,
            "ingest_ms": elapsed,
            "raw_count": len(alerts),
        },
    }


async def parallel_classify(
    state: AITriageAcceleratorState,
) -> dict[str, Any]:
    """Classify alerts in parallel batch mode."""
    start = time.time()
    toolkit = _get_toolkit()
    alerts = state.alert_batch.alerts

    # Heuristic batch classification
    classifications = await toolkit.batch_classify(alerts)

    # LLM enhancement per alert
    for i, cls in enumerate(classifications):
        try:
            alert = alerts[i] if i < len(alerts) else None
            if alert is None:
                continue
            context = _json.dumps(
                {
                    "title": alert.get("title", ""),
                    "description": alert.get(
                        "description",
                        "",
                    ),
                    "source": alert.get("source", ""),
                    "severity": alert.get("severity", ""),
                    "indicators": cls.indicators[:10],
                    "heuristic_cls": cls.classification.value,
                    "heuristic_conf": cls.confidence,
                },
                default=str,
            )
            llm_result = await llm_structured(
                system_prompt=SYSTEM_CLASSIFY,
                user_prompt=(f"Classify this alert:\n{context}"),
                schema=ClassifyOutput,
            )
            llm_cls = getattr(
                llm_result,
                "classification",
                "",
            )
            valid = [c.value for c in Classification]
            if llm_cls in valid:
                cls.classification = Classification(llm_cls)
            llm_conf = getattr(
                llm_result,
                "confidence",
                None,
            )
            if llm_conf is not None:
                cls.confidence = (cls.confidence + llm_conf) / 2
            llm_reason = getattr(
                llm_result,
                "reasoning",
                "",
            )
            if llm_reason:
                cls.reasoning = f"{cls.reasoning} | LLM: {llm_reason}"
            llm_mitre = getattr(
                llm_result,
                "mitre_tactics",
                [],
            )
            if llm_mitre:
                cls.mitre_tactics = llm_mitre
            logger.info(
                "llm_enhanced",
                node="parallel_classify",
                alert_id=cls.alert_id,
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="parallel_classify",
                index=i,
            )

    step = ReasoningStep(
        step="parallel_classify",
        detail=(f"Classified {len(classifications)} alert(s)"),
        confidence=("high" if all(c.confidence > 0.5 for c in classifications) else "medium"),
        metadata={
            "classification_dist": {
                c.value: sum(1 for r in classifications if r.classification == c)
                for c in Classification
            },
        },
    )

    elapsed = int((time.time() - start) * 1000)
    return {
        "classifications": classifications,
        "stage": TriageStage.ENRICH_CONTEXT,
        "current_step": "parallel_classify",
        "reasoning_chain": [*state.reasoning_chain, step],
        "stats": {
            **state.stats,
            "classify_ms": elapsed,
        },
    }


async def enrich_context(
    state: AITriageAcceleratorState,
) -> dict[str, Any]:
    """Enrich alerts with threat intel, identity, assets."""
    start = time.time()
    toolkit = _get_toolkit()
    alerts = state.alert_batch.alerts

    enrichments = await toolkit.enrich_alerts(
        alerts,
        state.classifications,
    )

    # LLM enhancement for enrichment
    for i, enr in enumerate(enrichments):
        try:
            alert = alerts[i] if i < len(alerts) else None
            if alert is None:
                continue
            cls = state.classifications[i] if i < len(state.classifications) else None
            context = _json.dumps(
                {
                    "title": alert.get("title", ""),
                    "description": alert.get(
                        "description",
                        "",
                    ),
                    "classification": (cls.classification.value if cls else "unknown"),
                    "threat_hits": len(
                        enr.threat_intel_hits,
                    ),
                    "asset_criticality": (enr.asset_criticality),
                },
                default=str,
            )
            llm_result = await llm_structured(
                system_prompt=SYSTEM_ENRICH,
                user_prompt=(f"Enrich this alert:\n{context}"),
                schema=EnrichOutput,
            )
            llm_crit = getattr(
                llm_result,
                "asset_criticality",
                "",
            )
            if llm_crit:
                enr.asset_criticality = llm_crit
            logger.info(
                "llm_enhanced",
                node="enrich_context",
                alert_id=enr.alert_id,
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="enrich_context",
                index=i,
            )

    step = ReasoningStep(
        step="enrich_context",
        detail=(f"Enriched {len(enrichments)} alert(s)"),
        confidence="high",
        metadata={
            "enrichment_count": len(enrichments),
        },
    )

    elapsed = int((time.time() - start) * 1000)
    return {
        "enrichments": enrichments,
        "stage": TriageStage.CONFIDENCE_SCORE,
        "current_step": "enrich_context",
        "reasoning_chain": [*state.reasoning_chain, step],
        "stats": {
            **state.stats,
            "enrich_ms": elapsed,
        },
    }


async def confidence_score(
    state: AITriageAcceleratorState,
) -> dict[str, Any]:
    """Compute confidence scores with reasoning chains."""
    start = time.time()
    toolkit = _get_toolkit()

    scores = await toolkit.score_confidence(
        state.classifications,
        state.enrichments,
    )

    # LLM enhancement for confidence scoring
    for i, sc in enumerate(scores):
        try:
            cls = state.classifications[i] if i < len(state.classifications) else None
            enr = state.enrichments[i] if i < len(state.enrichments) else None
            context = _json.dumps(
                {
                    "classification": (cls.classification.value if cls else "unknown"),
                    "heuristic_confidence": (cls.confidence if cls else 0.0),
                    "threat_hits": (len(enr.threat_intel_hits) if enr else 0),
                    "asset_criticality": (enr.asset_criticality if enr else "unknown"),
                    "current_score": sc.overall_score,
                },
                default=str,
            )
            llm_result = await llm_structured(
                system_prompt=SYSTEM_CONFIDENCE,
                user_prompt=(f"Score confidence:\n{context}"),
                schema=ConfidenceOutput,
            )
            llm_score = getattr(
                llm_result,
                "overall_score",
                None,
            )
            if llm_score is not None:
                sc.overall_score = (sc.overall_score + llm_score) / 2
            llm_chain = getattr(
                llm_result,
                "reasoning_chain",
                [],
            )
            if llm_chain:
                sc.reasoning_chain.extend(
                    [f"LLM: {r}" for r in llm_chain],
                )
            logger.info(
                "llm_enhanced",
                node="confidence_score",
                alert_id=sc.alert_id,
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="confidence_score",
                index=i,
            )

    step = ReasoningStep(
        step="confidence_score",
        detail=(
            f"Scored {len(scores)} alert(s), "
            f"avg={sum(s.overall_score for s in scores) / max(len(scores), 1):.2f}"
        ),
        confidence="high",
        metadata={
            "avg_confidence": (sum(s.overall_score for s in scores) / max(len(scores), 1)),
        },
    )

    elapsed = int((time.time() - start) * 1000)
    return {
        "confidence_scores": scores,
        "stage": TriageStage.ROUTE_DECISIONS,
        "current_step": "confidence_score",
        "reasoning_chain": [*state.reasoning_chain, step],
        "stats": {
            **state.stats,
            "confidence_ms": elapsed,
        },
    }


async def route_decisions(
    state: AITriageAcceleratorState,
) -> dict[str, Any]:
    """Route alerts to optimal response paths."""
    start = time.time()
    toolkit = _get_toolkit()

    actions = await toolkit.route_alerts(
        state.classifications,
        state.confidence_scores,
    )

    # LLM enhancement for routing
    for action in actions:
        try:
            cls_match = next(
                (c for c in state.classifications if c.alert_id == action.alert_id),
                None,
            )
            conf_match = next(
                (s for s in state.confidence_scores if s.alert_id == action.alert_id),
                None,
            )
            context = _json.dumps(
                {
                    "alert_id": action.alert_id,
                    "classification": (cls_match.classification.value if cls_match else "unknown"),
                    "confidence": (conf_match.overall_score if conf_match else 0.5),
                    "current_decision": (action.decision.value),
                    "current_team": action.assigned_team,
                },
                default=str,
            )
            llm_result = await llm_structured(
                system_prompt=SYSTEM_ROUTE,
                user_prompt=(f"Route this alert:\n{context}"),
                schema=RouteOutput,
            )
            llm_decision = getattr(
                llm_result,
                "decision",
                "",
            )
            valid_d = [d.value for d in RoutingDecision]
            if llm_decision in valid_d:
                action.decision = RoutingDecision(
                    llm_decision,
                )
            llm_team = getattr(
                llm_result,
                "assigned_team",
                "",
            )
            if llm_team:
                action.assigned_team = llm_team
            llm_reason = getattr(
                llm_result,
                "routing_reasoning",
                "",
            )
            if llm_reason:
                action.routing_reason = f"{action.routing_reason} | LLM: {llm_reason}"
            logger.info(
                "llm_enhanced",
                node="route_decisions",
                alert_id=action.alert_id,
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="route_decisions",
                alert_id=action.alert_id,
            )

    # Compute metrics
    auto_closed = sum(1 for a in actions if a.decision == RoutingDecision.AUTO_CLOSE)
    auto_rem = sum(1 for a in actions if a.decision == RoutingDecision.AUTO_REMEDIATE)
    escalated = sum(1 for a in actions if a.decision == RoutingDecision.ESCALATE_URGENT)
    total = max(len(actions), 1)

    # False positive rate = auto-closed / total
    fp_rate = auto_closed / total

    step = ReasoningStep(
        step="route_decisions",
        detail=(
            f"Routed {len(actions)} alert(s): "
            f"{auto_closed} auto-closed, "
            f"{auto_rem} auto-remediated, "
            f"{escalated} escalated"
        ),
        confidence="high",
        metadata={
            "auto_closed": auto_closed,
            "auto_remediated": auto_rem,
            "escalated": escalated,
            "false_positive_rate": fp_rate,
        },
    )

    elapsed = int((time.time() - start) * 1000)
    return {
        "routing_actions": actions,
        "false_positive_rate": fp_rate,
        "stage": TriageStage.REPORT,
        "current_step": "route_decisions",
        "reasoning_chain": [*state.reasoning_chain, step],
        "stats": {
            **state.stats,
            "route_ms": elapsed,
            "auto_closed": auto_closed,
            "auto_remediated": auto_rem,
            "escalated": escalated,
        },
    }


async def report(
    state: AITriageAcceleratorState,
) -> dict[str, Any]:
    """Generate triage acceleration report."""
    start = time.time()
    total_elapsed = int(
        (time.time() - state.session_start) * 1000,
    )

    # Compute speedup factor (vs ~5min manual per alert)
    manual_est_ms = len(state.alert_batch.alerts) * 300000
    speedup = manual_est_ms / max(total_elapsed, 1) if total_elapsed > 0 else 10.0

    # Classification distribution
    cls_dist: dict[str, int] = {}
    for cls in state.classifications:
        key = cls.classification.value
        cls_dist[key] = cls_dist.get(key, 0) + 1

    # Routing distribution
    route_dist: dict[str, int] = {}
    for act in state.routing_actions:
        key = act.decision.value
        route_dist[key] = route_dist.get(key, 0) + 1

    # Avg confidence
    avg_conf = sum(s.overall_score for s in state.confidence_scores) / max(
        len(state.confidence_scores), 1
    )

    report_stats: dict[str, Any] = {
        "total_alerts": len(state.alert_batch.alerts),
        "classification_distribution": cls_dist,
        "routing_distribution": route_dist,
        "avg_confidence": round(avg_conf, 3),
        "false_positive_rate": round(
            state.false_positive_rate,
            3,
        ),
        "speedup_factor": round(speedup, 1),
        "total_duration_ms": total_elapsed,
    }

    # LLM executive summary
    try:
        context = _json.dumps(
            {
                "stats": report_stats,
                "classifications": [c.model_dump() for c in state.classifications[:20]],
                "routing": [r.model_dump() for r in state.routing_actions[:20]],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate triage report:\n{context}"),
            schema=ReportOutput,
        )
        if hasattr(llm_result, "executive_summary"):
            report_stats["executive_summary"] = getattr(
                llm_result,
                "executive_summary",
                "",
            )
            report_stats["key_findings"] = getattr(
                llm_result,
                "key_findings",
                [],
            )
            report_stats["recommended_actions"] = getattr(
                llm_result,
                "recommended_actions",
                [],
            )
            report_stats["risk_assessment"] = getattr(
                llm_result,
                "risk_assessment",
                "",
            )
        logger.info("llm_enhanced", node="report")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="report",
        )

    step = ReasoningStep(
        step="report",
        detail=(
            f"Triage complete: {len(state.alert_batch.alerts)}"
            f" alerts in {total_elapsed}ms"
            f" ({speedup:.1f}x speedup)"
        ),
        confidence="high",
        metadata=report_stats,
    )

    elapsed = int((time.time() - start) * 1000)
    return {
        "accuracy_score": avg_conf,
        "speedup_factor": speedup,
        "stage": TriageStage.REPORT,
        "current_step": "report",
        "stats": {
            **state.stats,
            **report_stats,
            "report_ms": elapsed,
        },
        "reasoning_chain": [*state.reasoning_chain, step],
        "session_duration_ms": total_elapsed,
    }
