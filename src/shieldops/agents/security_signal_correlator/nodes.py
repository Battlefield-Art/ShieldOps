"""Security Signal Correlator Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    ConfidenceScore,
    Correlation,
    NormalizedSignal,
    ReasoningStep,
    SecuritySignal,
    SSCStage,
)
from .tools import SecuritySignalCorrelatorToolkit

logger = structlog.get_logger()

_toolkit: SecuritySignalCorrelatorToolkit | None = None  # noqa: PLW0603


def set_toolkit(tk: SecuritySignalCorrelatorToolkit) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = tk


def _get_toolkit() -> SecuritySignalCorrelatorToolkit:
    if _toolkit is None:
        msg = "Toolkit not initialized"
        raise RuntimeError(msg)
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Collect Signals
# ------------------------------------------------------------------


async def collect_signals(
    state: dict[str, Any],
    toolkit: SecuritySignalCorrelatorToolkit,
) -> dict[str, Any]:
    """Collect security signals from multiple sources."""
    logger.info("ssc.node.collect_signals")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    signals = await toolkit.collect_signals(tenant_id)
    data = [s.model_dump() for s in signals]

    note = f"Collected {len(signals)} security signals"

    return {
        "stage": SSCStage.NORMALIZE.value,
        "signals": data,
        "total_signals_collected": len(signals),
        "current_step": "collect_signals",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="collect_signals",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Normalize
# ------------------------------------------------------------------


async def normalize(
    state: dict[str, Any],
    toolkit: SecuritySignalCorrelatorToolkit,
) -> dict[str, Any]:
    """Normalize signals to common schema."""
    logger.info("ssc.node.normalize")
    state = _to_dict(state)

    signals = [SecuritySignal(**s) for s in state.get("signals", [])]
    normalized = await toolkit.normalize_signals(signals)
    data = [n.model_dump() for n in normalized]

    note = f"Normalized {len(normalized)} signals to common schema"

    return {
        "stage": SSCStage.CORRELATE.value,
        "normalized": data,
        "current_step": "normalize",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="normalize",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Correlate
# ------------------------------------------------------------------


async def correlate(
    state: dict[str, Any],
    toolkit: SecuritySignalCorrelatorToolkit,
) -> dict[str, Any]:
    """Correlate normalized signals."""
    logger.info("ssc.node.correlate")
    state = _to_dict(state)

    normalized = [NormalizedSignal(**n) for n in state.get("normalized", [])]
    correlations = await toolkit.correlate_events(normalized)
    data = [c.model_dump() for c in correlations]

    note = f"Found {len(correlations)} correlations across {len(normalized)} signals"

    try:
        from .prompts import SYSTEM_ANALYZE, CorrelationInsight

        ctx = json.dumps(
            {
                "correlations": [
                    {
                        "pattern": c.pattern,
                        "strength": c.strength.value,
                        "signals": len(c.signal_ids),
                        "entity": c.entity,
                    }
                    for c in correlations[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            CorrelationInsight,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"Signal correlations:\n{ctx}",
                schema=CorrelationInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="ssc",
            node="correlate",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="ssc",
            node="correlate",
        )

    return {
        "stage": SSCStage.SCORE_CONFIDENCE.value,
        "correlations": data,
        "current_step": "correlate",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="correlate",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Score Confidence
# ------------------------------------------------------------------


async def score_confidence(
    state: dict[str, Any],
    toolkit: SecuritySignalCorrelatorToolkit,
) -> dict[str, Any]:
    """Score confidence for each correlation."""
    logger.info("ssc.node.score_confidence")
    state = _to_dict(state)

    correlations = [Correlation(**c) for c in state.get("correlations", [])]
    normalized = [NormalizedSignal(**n) for n in state.get("normalized", [])]
    scores = await toolkit.score_confidence(correlations, normalized)
    data = [s.model_dump() for s in scores]

    actionable = sum(1 for s in scores if s.is_actionable)
    note = f"Scored {len(scores)} correlations, {actionable} actionable"

    return {
        "stage": SSCStage.GENERATE_INCIDENTS.value,
        "scores": data,
        "current_step": "score_confidence",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="score_confidence",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Generate Incidents
# ------------------------------------------------------------------


async def generate_incidents(
    state: dict[str, Any],
    toolkit: SecuritySignalCorrelatorToolkit,
) -> dict[str, Any]:
    """Generate incidents from high-confidence correlations."""
    logger.info("ssc.node.generate_incidents")
    state = _to_dict(state)

    correlations = [Correlation(**c) for c in state.get("correlations", [])]
    scores = [ConfidenceScore(**s) for s in state.get("scores", [])]
    incidents = await toolkit.generate_incidents(correlations, scores)
    data = [inc.model_dump() for inc in incidents]

    note = f"Generated {len(incidents)} incidents from correlations"

    return {
        "stage": SSCStage.REPORT.value,
        "incidents": data,
        "incidents_generated": len(incidents),
        "current_step": "generate_incidents",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="generate_incidents",
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
    toolkit: SecuritySignalCorrelatorToolkit,
) -> dict[str, Any]:
    """Compile the final signal correlation report."""
    logger.info("ssc.node.report")
    state = _to_dict(state)

    total_signals = state.get("total_signals_collected", 0)
    incident_count = state.get("incidents_generated", 0)
    corr_count = len(state.get("correlations", []))

    lines = [
        "# Security Signal Correlation Report",
        "",
        f"**Signals collected:** {total_signals}",
        f"**Correlations found:** {corr_count}",
        f"**Incidents generated:** {incident_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "total_signals": total_signals,
                "correlations": corr_count,
                "incidents": incident_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Signal correlation report:\n{ctx}",
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="ssc",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="ssc",
            node="report",
        )

    return {
        "stage": SSCStage.REPORT.value,
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
