"""Security Posture Scorer Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    CategoryWeight,
    PostureScore,
    ReasoningStep,
    SecuritySignal,
    SPSStage,
)
from .tools import SecurityPostureScorerToolkit

logger = structlog.get_logger()

_toolkit: SecurityPostureScorerToolkit | None = None  # noqa: PLW0603


def set_toolkit(tk: SecurityPostureScorerToolkit) -> None:
    """Set the module-level toolkit."""
    global _toolkit  # noqa: PLW0603
    _toolkit = tk


def _get_toolkit() -> SecurityPostureScorerToolkit:
    """Get the module-level toolkit."""
    if _toolkit is None:
        msg = "Toolkit not set — call set_toolkit first"
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
    toolkit: SecurityPostureScorerToolkit,
) -> dict[str, Any]:
    """Collect security signals from all sources."""
    logger.info("sps.node.collect_signals")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    signals = await toolkit.collect_signals(tenant_id)
    data = [s.model_dump() for s in signals]

    note = f"Collected {len(signals)} signals across sources"

    return {
        "stage": SPSStage.WEIGHT_CATEGORIES.value,
        "signals": data,
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
# Node 2: Weight Categories
# ------------------------------------------------------------------


async def weight_categories(
    state: dict[str, Any],
    toolkit: SecurityPostureScorerToolkit,
) -> dict[str, Any]:
    """Compute category weights."""
    logger.info("sps.node.weight_categories")
    state = _to_dict(state)

    signals = [SecuritySignal(**s) for s in state.get("signals", [])]
    weights = await toolkit.weight_categories(signals)
    data = [w.model_dump() for w in weights]

    note = f"Computed weights for {len(weights)} categories"

    return {
        "stage": SPSStage.CALCULATE_SCORES.value,
        "category_weights": data,
        "current_step": "weight_categories",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="weight_categories",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Calculate Scores
# ------------------------------------------------------------------


async def calculate_scores(
    state: dict[str, Any],
    toolkit: SecurityPostureScorerToolkit,
) -> dict[str, Any]:
    """Calculate posture scores per category."""
    logger.info("sps.node.calculate_scores")
    state = _to_dict(state)

    signals = [SecuritySignal(**s) for s in state.get("signals", [])]
    weights = [CategoryWeight(**w) for w in state.get("category_weights", [])]
    scores = await toolkit.calculate_scores(signals, weights)
    data = [s.model_dump() for s in scores]

    overall = round(sum(s.score for s in scores) / len(scores), 1) if scores else 0.0
    note = f"Calculated {len(scores)} category scores, overall {overall}"

    try:
        from .prompts import SYSTEM_ANALYZE, ScoreInsight

        ctx = json.dumps(
            {
                "scores": [
                    {
                        "category": s.category,
                        "score": s.score,
                        "tier": s.tier.value,
                    }
                    for s in scores[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ScoreInsight,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"Posture scores:\n{ctx}",
                schema=ScoreInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="sps",
            node="calculate_scores",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="sps",
            node="calculate_scores",
        )

    from .tools import _score_to_tier

    return {
        "stage": SPSStage.BENCHMARK.value,
        "scores": data,
        "overall_score": overall,
        "overall_tier": _score_to_tier(overall).value,
        "current_step": "calculate_scores",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="calculate_scores",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Benchmark
# ------------------------------------------------------------------


async def benchmark(
    state: dict[str, Any],
    toolkit: SecurityPostureScorerToolkit,
) -> dict[str, Any]:
    """Compare scores against industry benchmarks."""
    logger.info("sps.node.benchmark")
    state = _to_dict(state)

    scores = [PostureScore(**s) for s in state.get("scores", [])]
    benchmarks = await toolkit.benchmark_comparison(scores)
    data = [b.model_dump() for b in benchmarks]

    below_avg = sum(1 for b in benchmarks if b.org_score < b.industry_avg)
    note = f"Benchmarked {len(benchmarks)} categories, {below_avg} below average"

    return {
        "stage": SPSStage.TREND_ANALYSIS.value,
        "benchmarks": data,
        "current_step": "benchmark",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="benchmark",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Trend Analysis
# ------------------------------------------------------------------


async def trend_analysis(
    state: dict[str, Any],
    toolkit: SecurityPostureScorerToolkit,
) -> dict[str, Any]:
    """Analyze posture score trends."""
    logger.info("sps.node.trend_analysis")
    state = _to_dict(state)

    scores = [PostureScore(**s) for s in state.get("scores", [])]
    trends = await toolkit.analyze_trends(scores)
    data = [t.model_dump() for t in trends]

    improving = sum(1 for t in trends if t.direction == "improving")
    note = f"Analyzed {len(trends)} periods, {improving} improving"

    return {
        "stage": SPSStage.REPORT.value,
        "trends": data,
        "current_step": "trend_analysis",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="trend_analysis",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: SecurityPostureScorerToolkit,
) -> dict[str, Any]:
    """Compile the final security posture report."""
    logger.info("sps.node.report")
    state = _to_dict(state)

    overall = state.get("overall_score", 0.0)
    tier = state.get("overall_tier", "")
    score_count = len(state.get("scores", []))
    bench_count = len(state.get("benchmarks", []))

    lines = [
        "# Security Posture Report",
        "",
        f"**Overall Score:** {overall}/100 ({tier})",
        f"**Categories scored:** {score_count}",
        f"**Benchmarks compared:** {bench_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "overall_score": overall,
                "tier": tier,
                "categories": score_count,
                "benchmarks": bench_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Posture report:\n{ctx}",
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="sps",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="sps",
            node="report",
        )

    return {
        "stage": SPSStage.REPORT.value,
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
