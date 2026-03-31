"""Node implementations for the Security Copilot Agent
LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_copilot_agent.models import (
    ReasoningStep,
    SCAStage,
    SecurityCopilotAgentState,
)
from shieldops.agents.security_copilot_agent.prompts import (
    SYSTEM_ANALYSIS,
    SYSTEM_QUERY_PARSE,
    SYSTEM_RECOMMEND,
    SYSTEM_REPORT,
    AnalysisOutput,
    QueryParsingOutput,
    RecommendationOutput,
    ReportOutput,
)
from shieldops.agents.security_copilot_agent.tools import (
    SecurityCopilotAgentToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityCopilotAgentToolkit | None = None


def set_toolkit(
    toolkit: SecurityCopilotAgentToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SecurityCopilotAgentToolkit:
    if _toolkit is None:
        return SecurityCopilotAgentToolkit()
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
# Node: receive_query
# ------------------------------------------------------------------


async def receive_query(
    state: SecurityCopilotAgentState,
) -> dict[str, Any]:
    """Parse the analyst's natural language query into
    structured intent with entity extraction."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    parsed = await toolkit.receive_query(
        raw_query=state.raw_query,
        analyst_id=state.analyst_id,
        session_history=state.session_history,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "query": state.raw_query,
                "analyst_id": state.analyst_id,
                "history_len": len(state.session_history),
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_QUERY_PARSE,
            user_prompt=f"Parse this query:\n{ctx}",
            schema=QueryParsingOutput,
        )
        if llm_out.intent:  # type: ignore[union-attr]
            parsed = {
                "category": llm_out.category,  # type: ignore[union-attr]
                "intent": llm_out.intent,  # type: ignore[union-attr]
                "entities": llm_out.entities,  # type: ignore[union-attr]
                "urgency": llm_out.urgency,  # type: ignore[union-attr]
            }
        logger.info(
            "llm_enhanced",
            node="receive_query",
            category=llm_out.category,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="receive_query",
        )

    step = _step(
        state.reasoning_chain,
        "receive_query",
        f"Query: {state.raw_query[:80]}",
        f"Parsed category={parsed.get('category', 'unknown')}",
        start,
        "query_parser",
    )

    return {
        "parsed_query": parsed,
        "stage": SCAStage.RECEIVE_QUERY,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "receive_query",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: gather_context
# ------------------------------------------------------------------


async def gather_context(
    state: SecurityCopilotAgentState,
) -> dict[str, Any]:
    """Gather security context from data sources based
    on parsed query entities."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    entities = state.parsed_query.get("entities", [])
    context = await toolkit.gather_context(
        parsed_query=state.parsed_query,
        entities=entities,
    )

    step = _step(
        state.reasoning_chain,
        "gather_context",
        f"Querying context for {len(entities)} entities",
        f"Gathered {len(context)} context items",
        start,
        "context_engine",
    )

    return {
        "context": context,
        "stage": SCAStage.GATHER_CONTEXT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "gather_context",
    }


# ------------------------------------------------------------------
# Node: analyze
# ------------------------------------------------------------------


async def analyze(
    state: SecurityCopilotAgentState,
) -> dict[str, Any]:
    """Analyze gathered context to produce security
    findings and risk assessment."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    analysis = await toolkit.analyze_situation(
        context=state.context,
        parsed_query=state.parsed_query,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "query": state.raw_query,
                "parsed": state.parsed_query,
                "context_count": len(state.context),
                "context_sample": state.context[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ANALYSIS,
            user_prompt=f"Analyze context:\n{ctx}",
            schema=AnalysisOutput,
        )
        if llm_out.findings:  # type: ignore[union-attr]
            rand_id = random.randint(1000, 9999)  # noqa: S311
            analysis.append(
                {
                    "analysis_id": f"llm-{rand_id}",
                    "findings": llm_out.findings,  # type: ignore[union-attr]
                    "risk_score": llm_out.risk_score,  # type: ignore[union-attr]
                    "attack_stage": llm_out.attack_stage,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="analyze",
            findings=len(llm_out.findings),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze",
        )

    step = _step(
        state.reasoning_chain,
        "analyze",
        f"Analyzing {len(state.context)} context items",
        f"Produced {len(analysis)} analysis results",
        start,
        "analyzer",
    )

    return {
        "analysis": analysis,
        "stage": SCAStage.ANALYZE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze",
    }


# ------------------------------------------------------------------
# Node: recommend
# ------------------------------------------------------------------


async def recommend(
    state: SecurityCopilotAgentState,
) -> dict[str, Any]:
    """Generate prioritized action recommendations
    from the analysis results."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    recommendations = await toolkit.recommend_actions(
        analysis=state.analysis,
        parsed_query=state.parsed_query,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "query": state.raw_query,
                "analysis": state.analysis[:5],
                "parsed": state.parsed_query,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_RECOMMEND,
            user_prompt=f"Recommend actions:\n{ctx}",
            schema=RecommendationOutput,
        )
        if llm_out.recommendations:  # type: ignore[union-attr]
            recommendations = [
                *recommendations,
                *llm_out.recommendations,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="recommend",
            count=len(llm_out.recommendations),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="recommend",
        )

    step = _step(
        state.reasoning_chain,
        "recommend",
        f"Analyzing {len(state.analysis)} results",
        f"Generated {len(recommendations)} recommendations",
        start,
        "recommender",
    )

    return {
        "recommendations": recommendations,
        "stage": SCAStage.RECOMMEND,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "recommend",
    }


# ------------------------------------------------------------------
# Node: execute_action
# ------------------------------------------------------------------


async def execute_action(
    state: SecurityCopilotAgentState,
) -> dict[str, Any]:
    """Execute approved automated actions from
    recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    action_results: list[dict[str, Any]] = []
    actions_taken = 0

    for rec in state.recommendations:
        if not rec.get("automated", False):
            continue
        result = await toolkit.execute_action(
            recommendation=rec,
            analyst_id=state.analyst_id,
        )
        action_results.append(result)
        if result.get("success"):
            actions_taken += 1

    step = _step(
        state.reasoning_chain,
        "execute_action",
        f"Executing {len(state.recommendations)} recs",
        f"{actions_taken} actions succeeded",
        start,
        "action_engine",
    )

    return {
        "action_results": action_results,
        "actions_taken": actions_taken,
        "stage": SCAStage.EXECUTE_ACTION,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "execute_action",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: SecurityCopilotAgentState,
) -> dict[str, Any]:
    """Generate the copilot session report with summary
    and follow-up items."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    total = len(state.analysis) + len(state.recommendations)
    confidence = min(1.0, 0.4 + total * 0.05) if total > 0 else 0.1

    report: dict[str, Any] = {
        "query": state.raw_query,
        "actions_taken": state.actions_taken,
        "confidence": confidence,
    }

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "query": state.raw_query,
                "parsed": state.parsed_query,
                "analysis_count": len(state.analysis),
                "recommendations_count": len(state.recommendations),
                "actions_taken": state.actions_taken,
                "action_results": state.action_results[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate session report:\n{ctx}",
            schema=ReportOutput,
        )
        if isinstance(llm_out, ReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "query_resolved": llm_out.query_resolved,
                    "actions_list": llm_out.actions_taken,
                    "follow_up_items": llm_out.follow_up_items,
                    "knowledge_gained": llm_out.knowledge_gained,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                resolved=llm_out.query_resolved,
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    # Record metrics
    await toolkit.record_metric(
        request_id=state.request_id,
        outcome={
            "query_resolved": state.query_resolved,
            "actions_taken": state.actions_taken,
            "confidence": confidence,
        },
    )

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.actions_taken} actions",
        f"Report generated, confidence={confidence:.2f}",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "confidence_score": confidence,
        "query_resolved": report.get("query_resolved", False),
        "session_duration_ms": duration_ms,
        "stage": SCAStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
