"""Spam Filter Manager Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import ClassificationResult, SpamRule, SpamStage
from .tools import SpamFilterManagerToolkit

logger = structlog.get_logger()

_toolkit: SpamFilterManagerToolkit | None = None


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def collect_rules(
    state: dict[str, Any],
    toolkit: SpamFilterManagerToolkit,
) -> dict[str, Any]:
    """Collect current spam filter rules."""
    logger.info("spam_filter.node.collect_rules")
    state = _to_dict(state)
    tenant_id = state.get("tenant_id", "")

    rules = await toolkit.collect_rules(tenant_id)
    rule_dicts = [r.model_dump() for r in rules]

    return {
        "rules": rule_dicts,
        "total_rules": len(rules),
        "stage": SpamStage.COLLECT_RULES.value,
        "session_start": time.time(),
        "current_step": "collect_rules",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Collected {len(rules)} filter rules"],
    }


async def classify_messages(
    state: dict[str, Any],
    toolkit: SpamFilterManagerToolkit,
) -> dict[str, Any]:
    """Classify messages using rules."""
    logger.info("spam_filter.node.classify_messages")
    state = _to_dict(state)
    raw_rules = state.get("rules", [])

    rules = [SpamRule(**r) if isinstance(r, dict) else r for r in raw_rules]
    classifications, spam_count = await toolkit.classify_messages(rules)

    reasoning_note = f"Classified {len(classifications)} messages, {spam_count} spam detected"

    try:
        from .prompts import (
            SYSTEM_CLASSIFICATION,
            ClassificationOutput,
        )

        context = json.dumps(
            {
                "count": len(classifications),
                "spam": spam_count,
                "samples": [c.model_dump() for c in classifications[:10]],
            },
            default=str,
        )
        llm_out = cast(
            ClassificationOutput,
            await llm_structured(
                system_prompt=SYSTEM_CLASSIFICATION,
                user_prompt=(f"Message classifications:\n{context}"),
                schema=ClassificationOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="spam_filter_manager",
            node="classify_messages",
        )
        reasoning_note = f"{llm_out.summary} [confidence={llm_out.confidence:.0%}]"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="spam_filter_manager",
            node="classify_messages",
        )

    return {
        "classifications": [c.model_dump() for c in classifications],
        "messages_classified": len(classifications),
        "spam_detected": spam_count,
        "stage": SpamStage.CLASSIFY_MESSAGES.value,
        "current_step": "classify_messages",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning_note]),
    }


async def tune_filters(
    state: dict[str, Any],
    toolkit: SpamFilterManagerToolkit,
) -> dict[str, Any]:
    """Tune filter rules based on performance."""
    logger.info("spam_filter.node.tune_filters")
    state = _to_dict(state)
    raw_rules = state.get("rules", [])
    raw_cls = state.get("classifications", [])

    rules = [SpamRule(**r) if isinstance(r, dict) else r for r in raw_rules]
    classifications = [ClassificationResult(**c) if isinstance(c, dict) else c for c in raw_cls]

    suggestions = await toolkit.tune_filters(
        rules,
        classifications,
    )

    reasoning_note = f"Generated {len(suggestions)} tuning suggestions"

    try:
        from .prompts import (
            SYSTEM_FILTER_TUNING,
            FilterTuningOutput,
        )

        context = json.dumps(
            {
                "rules": [r.model_dump() for r in rules],
                "suggestions": suggestions,
            },
            default=str,
        )
        llm_out = cast(
            FilterTuningOutput,
            await llm_structured(
                system_prompt=SYSTEM_FILTER_TUNING,
                user_prompt=f"Filter tuning:\n{context}",
                schema=FilterTuningOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="spam_filter_manager",
            node="tune_filters",
        )
        reasoning_note = (
            f"{llm_out.summary} [est FP reduction={llm_out.estimated_fp_reduction:.0%}]"
        )
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="spam_filter_manager",
            node="tune_filters",
        )

    return {
        "tuning_suggestions": suggestions,
        "rules_tuned": len(suggestions),
        "stage": SpamStage.TUNE_FILTERS.value,
        "current_step": "tune_filters",
        "reasoning_chain": (state.get("reasoning_chain", []) + [reasoning_note]),
    }


async def analyze_false_positives(
    state: dict[str, Any],
    toolkit: SpamFilterManagerToolkit,
) -> dict[str, Any]:
    """Analyze false positive patterns."""
    logger.info("spam_filter.node.analyze_fps")
    state = _to_dict(state)
    raw_cls = state.get("classifications", [])

    classifications = [ClassificationResult(**c) if isinstance(c, dict) else c for c in raw_cls]
    fps, fp_rate = await toolkit.analyze_false_positives(
        classifications,
    )

    return {
        "false_positives": fps,
        "false_positive_rate": fp_rate,
        "stage": SpamStage.ANALYZE_FALSE_POSITIVES.value,
        "current_step": "analyze_false_positives",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"False positive analysis: {len(fps)} FPs ({fp_rate:.1%} rate)"],
    }


async def manage_quarantine(
    state: dict[str, Any],
    toolkit: SpamFilterManagerToolkit,
) -> dict[str, Any]:
    """Manage quarantined messages."""
    logger.info("spam_filter.node.manage_quarantine")
    state = _to_dict(state)
    raw_cls = state.get("classifications", [])

    classifications = [ClassificationResult(**c) if isinstance(c, dict) else c for c in raw_cls]
    items, count = await toolkit.manage_quarantine(
        classifications,
    )

    return {
        "quarantine_items": items,
        "quarantine_count": count,
        "stage": SpamStage.MANAGE_QUARANTINE.value,
        "current_step": "manage_quarantine",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Quarantine: {count} messages managed"],
    }


async def generate_report(
    state: dict[str, Any],
    toolkit: SpamFilterManagerToolkit,
) -> dict[str, Any]:
    """Generate final spam filter report."""
    logger.info("spam_filter.node.generate_report")
    state = _to_dict(state)

    session_start = state.get("session_start", time.time())
    duration_ms = (time.time() - session_start) * 1000

    stats = {
        "total_rules": state.get("total_rules", 0),
        "messages_classified": state.get("messages_classified", 0),
        "spam_detected": state.get("spam_detected", 0),
        "rules_tuned": state.get("rules_tuned", 0),
        "false_positive_rate": state.get("false_positive_rate", 0.0),
        "quarantine_count": state.get("quarantine_count", 0),
        "analysis_duration_ms": round(duration_ms, 2),
    }

    return {
        "stats": stats,
        "stage": SpamStage.REPORT.value,
        "current_step": "generate_report",
        "session_duration_ms": duration_ms,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Report: {stats['messages_classified']} msgs, "
            f"{stats['spam_detected']} spam, "
            f"{stats['false_positive_rate']:.1%} FP rate"
        ],
    }
