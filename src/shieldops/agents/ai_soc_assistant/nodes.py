"""Node implementations for the AI SOC Assistant Agent."""

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.ai_soc_assistant.models import (
    AISOCAssistantState,
    AnalystQuery,
    AssistantResponse,
    ContextGathering,
    ReasoningResult,
    SuggestedAction,
)
from shieldops.agents.ai_soc_assistant.prompts import (
    SYSTEM_ACTIONS,
    SYSTEM_PARSE_QUERY,
    SYSTEM_PRESENT,
    SYSTEM_REASON,
    ActionsOutput,
    ParsedQueryOutput,
    PresentationOutput,
    ReasoningOutput,
)
from shieldops.agents.ai_soc_assistant.tools import (
    AISOCAssistantToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AISOCAssistantToolkit | None = None


def _get_toolkit() -> AISOCAssistantToolkit:
    if _toolkit is None:
        return AISOCAssistantToolkit()
    return _toolkit


async def parse_query(
    state: AISOCAssistantState,
) -> dict[str, Any]:
    """Parse natural language query using LLM."""
    start = datetime.now(UTC)

    raw_query = state.query
    parsed = AnalystQuery(raw_query=raw_query)

    try:
        llm_result = await llm_structured(
            system_prompt=SYSTEM_PARSE_QUERY,
            user_prompt=f"Analyst query: {raw_query}",
            schema=ParsedQueryOutput,
        )
        parsed = AnalystQuery(
            raw_query=raw_query,
            query_type=llm_result.query_type,
            entities=llm_result.entities,
            time_range=llm_result.time_range,
            intent=llm_result.intent,
        )
        logger.info(
            "llm_enhanced",
            node="parse_query",
            query_type=parsed.query_type,
            entity_count=len(parsed.entities),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="parse_query",
        )
        # Fallback: basic extraction
        parsed = AnalystQuery(
            raw_query=raw_query,
            query_type="investigation",
            entities=_extract_entities(raw_query),
            time_range="24h",
            intent=raw_query[:100],
        )

    elapsed = (datetime.now(UTC) - start).total_seconds()
    logger.info(
        "ai_soc_assistant.parse_query",
        query_type=parsed.query_type,
        entities=parsed.entities,
        elapsed_s=round(elapsed, 3),
    )

    return {
        "parsed_query": parsed,
        "current_step": "parse_query",
        "session_start": start,
    }


async def gather_context(
    state: AISOCAssistantState,
) -> dict[str, Any]:
    """Gather cross-vendor context for the parsed query."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    pq = state.parsed_query or AnalystQuery()
    entities = pq.entities
    time_range = pq.time_range

    # Parallel cross-vendor queries
    siem_results = await toolkit.search_siem(
        pq.raw_query,
        time_range=time_range,
        entities=entities,
    )
    edr_results = await toolkit.query_edr(
        entities,
        time_range=time_range,
    )
    identity_results = await toolkit.check_identity(
        entities,
        time_range=time_range,
    )
    cloud_results = await toolkit.scan_cloud(
        entities,
        time_range=time_range,
    )

    vendor_sources: list[str] = []
    if siem_results:
        vendor_sources.append("siem")
    if edr_results:
        vendor_sources.append("edr")
    if identity_results:
        vendor_sources.append("identity")
    if cloud_results:
        vendor_sources.append("cloud")

    total_events = len(siem_results) + len(edr_results) + len(identity_results) + len(cloud_results)

    context = ContextGathering(
        siem_results=siem_results,
        edr_results=edr_results,
        identity_results=identity_results,
        cloud_results=cloud_results,
        vendor_sources=vendor_sources,
        total_events=total_events,
    )

    elapsed = (datetime.now(UTC) - start).total_seconds()
    logger.info(
        "ai_soc_assistant.gather_context",
        vendor_count=len(vendor_sources),
        total_events=total_events,
        elapsed_s=round(elapsed, 3),
    )

    return {
        "context_gathered": context,
        "current_step": "gather_context",
    }


async def reason_about_findings(
    state: AISOCAssistantState,
) -> dict[str, Any]:
    """Use LLM to reason about gathered findings."""
    start = datetime.now(UTC)

    ctx = state.context_gathered or ContextGathering()
    pq = state.parsed_query or AnalystQuery()

    reasoning = ReasoningResult(
        summary="No significant findings.",
        risk_level="info",
        confidence=0.5,
    )

    try:
        context_payload = _json.dumps(
            {
                "query": pq.raw_query,
                "query_type": pq.query_type,
                "entities": pq.entities,
                "siem_events": ctx.siem_results[:20],
                "edr_events": ctx.edr_results[:20],
                "identity_events": (ctx.identity_results[:20]),
                "cloud_events": ctx.cloud_results[:20],
                "vendor_sources": ctx.vendor_sources,
                "total_events": ctx.total_events,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REASON,
            user_prompt=(
                f"Analyst query: {pq.raw_query}\n\nCross-vendor context:\n{context_payload}"
            ),
            schema=ReasoningOutput,
        )
        reasoning = ReasoningResult(
            summary=llm_result.summary,
            key_findings=llm_result.key_findings,
            risk_level=llm_result.risk_level,
            confidence=llm_result.confidence,
            evidence_chain=llm_result.evidence_chain,
            mitre_techniques=(llm_result.mitre_techniques),
        )
        logger.info(
            "llm_enhanced",
            node="reason_about_findings",
            risk=reasoning.risk_level,
            confidence=reasoning.confidence,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="reason_about_findings",
        )

    elapsed = (datetime.now(UTC) - start).total_seconds()
    logger.info(
        "ai_soc_assistant.reason",
        risk_level=reasoning.risk_level,
        findings=len(reasoning.key_findings),
        elapsed_s=round(elapsed, 3),
    )

    return {
        "reasoning": reasoning,
        "current_step": "reason_about_findings",
    }


async def generate_actions(
    state: AISOCAssistantState,
) -> dict[str, Any]:
    """Generate suggested actions using LLM."""
    start = datetime.now(UTC)

    reasoning = state.reasoning or ReasoningResult()
    pq = state.parsed_query or AnalystQuery()
    actions: list[SuggestedAction] = []

    try:
        action_context = _json.dumps(
            {
                "query": pq.raw_query,
                "query_type": pq.query_type,
                "risk_level": reasoning.risk_level,
                "confidence": reasoning.confidence,
                "key_findings": reasoning.key_findings,
                "mitre_techniques": (reasoning.mitre_techniques),
                "evidence": reasoning.evidence_chain,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ACTIONS,
            user_prompt=(f"Analysis context:\n{action_context}"),
            schema=ActionsOutput,
        )
        for act in llm_result.actions:
            actions.append(
                SuggestedAction(
                    action_type=act.get(
                        "action_type",
                        "search_siem",
                    ),
                    description=act.get(
                        "description",
                        "",
                    ),
                    target=act.get("target", ""),
                    confidence=float(
                        act.get("confidence", 0.5),
                    ),
                    auto_executable=act.get(
                        "auto_executable",
                        "false",
                    )
                    == "true",
                ),
            )
        logger.info(
            "llm_enhanced",
            node="generate_actions",
            action_count=len(actions),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_actions",
        )
        # Fallback: suggest basic investigation
        actions.append(
            SuggestedAction(
                action_type="search_siem",
                description=("Search SIEM for related events"),
                target=", ".join(pq.entities[:3]),
                confidence=0.6,
            ),
        )

    elapsed = (datetime.now(UTC) - start).total_seconds()
    logger.info(
        "ai_soc_assistant.generate_actions",
        action_count=len(actions),
        elapsed_s=round(elapsed, 3),
    )

    return {
        "suggested_actions": actions,
        "current_step": "generate_actions",
    }


async def present_results(
    state: AISOCAssistantState,
) -> dict[str, Any]:
    """Format results into analyst-friendly response."""
    start = datetime.now(UTC)

    reasoning = state.reasoning or ReasoningResult()
    pq = state.parsed_query or AnalystQuery()
    actions = state.suggested_actions

    response = AssistantResponse(
        answer=reasoning.summary,
        evidence=reasoning.evidence_chain,
        sources=(state.context_gathered.vendor_sources if state.context_gathered else []),
    )

    try:
        present_context = _json.dumps(
            {
                "query": pq.raw_query,
                "summary": reasoning.summary,
                "key_findings": reasoning.key_findings,
                "risk_level": reasoning.risk_level,
                "evidence": reasoning.evidence_chain,
                "mitre": reasoning.mitre_techniques,
                "actions": [a.model_dump() for a in actions],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_PRESENT,
            user_prompt=(f"Format this analysis for the analyst:\n{present_context}"),
            schema=PresentationOutput,
        )
        response = AssistantResponse(
            answer=llm_result.answer,
            evidence=llm_result.evidence,
            follow_up_suggestions=(llm_result.follow_up_suggestions),
            sources=(state.context_gathered.vendor_sources if state.context_gathered else []),
        )
        logger.info(
            "llm_enhanced",
            node="present_results",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="present_results",
        )

    elapsed = (datetime.now(UTC) - start).total_seconds()
    logger.info(
        "ai_soc_assistant.present_results",
        answer_len=len(response.answer),
        elapsed_s=round(elapsed, 3),
    )

    return {
        "response": response,
        "current_step": "present_results",
    }


async def report(
    state: AISOCAssistantState,
) -> dict[str, Any]:
    """Finalize and record metrics."""
    toolkit = _get_toolkit()

    duration_s = 0.0
    if state.session_start:
        duration_s = (datetime.now(UTC) - state.session_start).total_seconds()

    queries_handled = state.queries_handled + 1
    prev_total = state.avg_response_time_seconds * state.queries_handled
    avg_time = (prev_total + duration_s) / queries_handled

    await toolkit.record_metric(
        "query_response_time_s",
        duration_s,
    )
    await toolkit.record_metric(
        "queries_handled",
        float(queries_handled),
    )

    logger.info(
        "ai_soc_assistant.report",
        duration_s=round(duration_s, 3),
        queries_handled=queries_handled,
        avg_response_time_s=round(avg_time, 3),
    )

    return {
        "queries_handled": queries_handled,
        "avg_response_time_seconds": avg_time,
        "current_step": "complete",
    }


def _extract_entities(query: str) -> list[str]:
    """Basic entity extraction fallback."""
    import re

    entities: list[str] = []
    # IPs
    ip_pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
    entities.extend(re.findall(ip_pattern, query))
    # Emails
    email_pattern = r"\b[\w.+-]+@[\w-]+\.[\w.]+\b"
    entities.extend(re.findall(email_pattern, query))
    # Hostnames (simple)
    host_pattern = r"\b(?:[a-zA-Z][\w-]*\.)+(?:com|net|org|io)\b"
    entities.extend(re.findall(host_pattern, query))
    return entities
