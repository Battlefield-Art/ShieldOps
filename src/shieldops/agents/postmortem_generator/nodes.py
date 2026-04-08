"""Node implementations for the Postmortem Generator."""

from __future__ import annotations

import json as _json
import time
from typing import Any

import structlog

from shieldops.utils.llm import llm_structured

from .models import PMGStage
from .prompts import (
    SYSTEM_ANALYZE,
    SYSTEM_REPORT,
    AnalyzeOutput,
    ReportOutput,
)
from .tools import PostmortemGeneratorToolkit

logger = structlog.get_logger()

_toolkit: PostmortemGeneratorToolkit | None = None


def _get_toolkit() -> PostmortemGeneratorToolkit:
    if _toolkit is None:
        return PostmortemGeneratorToolkit()
    return _toolkit


async def collect_timeline(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Collect incident timeline."""
    start = time.time()
    tk = _get_toolkit()

    events = await tk.collect_timeline(
        incident_id=state.get("incident_id", ""),
        incident_description=state.get(
            "incident_description",
            "",
        ),
        resolution_summary=state.get(
            "resolution_summary",
            "",
        ),
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "collect_timeline",
        "stage": PMGStage.ANALYZE_ROOT_CAUSE.value,
        "timeline_events": events,
        "reasoning_chain": [
            *chain,
            {
                "step": "collect_timeline",
                "detail": f"Events={len(events)}",
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "timeline_ms": elapsed,
        },
    }


async def analyze_root_cause(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Analyze root cause."""
    start = time.time()
    tk = _get_toolkit()

    result = await tk.analyze_root_cause(
        timeline_events=state.get(
            "timeline_events",
            [],
        ),
        incident_description=state.get(
            "incident_description",
            "",
        ),
        affected_services=state.get(
            "affected_services",
            [],
        ),
    )

    try:
        ctx = _json.dumps(
            {
                "timeline": state.get(
                    "timeline_events",
                    [],
                )[:10],
                "description": state.get(
                    "incident_description",
                    "",
                ),
                "services": state.get(
                    "affected_services",
                    [],
                ),
            },
            default=str,
        )
        llm = await llm_structured(
            system_prompt=SYSTEM_ANALYZE,
            user_prompt=f"Analyze root cause:\n{ctx}",
            schema=AnalyzeOutput,
        )
        if hasattr(llm, "root_cause") and llm.root_cause:
            result["llm_root_cause"] = llm.root_cause
        if hasattr(llm, "five_whys"):
            result["five_whys"] = llm.five_whys
    except Exception:
        logger.debug("pmg.llm_skipped", node="rca")

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "analyze_root_cause",
        "stage": PMGStage.IDENTIFY_ACTIONS.value,
        "root_cause_analysis": result,
        "reasoning_chain": [
            *chain,
            {
                "step": "analyze_root_cause",
                "detail": (f"Category={result.get('category')}"),
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "rca_ms": elapsed,
        },
    }


async def identify_actions(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Identify action items."""
    start = time.time()
    tk = _get_toolkit()

    actions = await tk.identify_actions(
        root_cause_analysis=state.get(
            "root_cause_analysis",
            {},
        ),
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "identify_actions",
        "stage": PMGStage.DRAFT_DOCUMENT.value,
        "action_items": actions,
        "reasoning_chain": [
            *chain,
            {
                "step": "identify_actions",
                "detail": f"Actions={len(actions)}",
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "actions_ms": elapsed,
        },
    }


async def draft_document(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Draft the postmortem document."""
    start = time.time()
    tk = _get_toolkit()

    doc = await tk.draft_document(
        incident_title=state.get("incident_title", ""),
        timeline_events=state.get(
            "timeline_events",
            [],
        ),
        root_cause_analysis=state.get(
            "root_cause_analysis",
            {},
        ),
        action_items=state.get("action_items", []),
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "draft_document",
        "stage": PMGStage.REVIEW_QUALITY.value,
        "document_draft": doc,
        "reasoning_chain": [
            *chain,
            {
                "step": "draft_document",
                "detail": "Document drafted",
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "draft_ms": elapsed,
        },
    }


async def review_quality(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Review postmortem quality."""
    start = time.time()
    tk = _get_toolkit()

    review = await tk.review_quality(
        document_draft=state.get("document_draft", {}),
        action_items=state.get("action_items", []),
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "review_quality",
        "stage": PMGStage.REPORT.value,
        "quality_review": review,
        "reasoning_chain": [
            *chain,
            {
                "step": "review_quality",
                "detail": (f"Quality={review.get('quality')}"),
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "review_ms": elapsed,
        },
    }


async def report(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Generate postmortem summary report."""
    start = time.time()
    report_data: dict[str, Any] = {
        "timeline_events": len(
            state.get("timeline_events", []),
        ),
        "action_items": len(
            state.get("action_items", []),
        ),
        "quality": state.get(
            "quality_review",
            {},
        ).get("quality", "unknown"),
        "category": state.get(
            "root_cause_analysis",
            {},
        ).get("category", "unknown"),
    }

    try:
        ctx = _json.dumps(report_data, default=str)
        llm = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate report:\n{ctx}",
            schema=ReportOutput,
        )
        if hasattr(llm, "executive_summary"):
            report_data["executive_summary"] = llm.executive_summary
            report_data["lessons_learned"] = llm.lessons_learned
    except Exception:
        logger.debug("pmg.llm_skipped", node="report")

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "report",
        "stage": PMGStage.REPORT.value,
        "stats": {
            **state.get("stats", {}),
            **report_data,
            "report_ms": elapsed,
        },
        "reasoning_chain": [
            *chain,
            {
                "step": "report",
                "detail": "Postmortem report generated",
                "elapsed_ms": elapsed,
            },
        ],
    }
