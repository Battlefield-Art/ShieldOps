"""Node implementations for the On-Call Optimizer."""

from __future__ import annotations

import json as _json
import time
from typing import Any

import structlog

from shieldops.utils.llm import llm_structured

from .models import OCOStage
from .prompts import (
    SYSTEM_ANALYZE,
    SYSTEM_REPORT,
    AnalyzeOutput,
    ReportOutput,
)
from .tools import OnCallOptimizerToolkit

logger = structlog.get_logger()

_toolkit: OnCallOptimizerToolkit | None = None


def _get_toolkit() -> OnCallOptimizerToolkit:
    if _toolkit is None:
        return OnCallOptimizerToolkit()
    return _toolkit


async def analyze_schedules(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Analyze on-call schedules."""
    start = time.time()
    tk = _get_toolkit()

    result = await tk.analyze_schedules(
        team_id=state.get("team_id", ""),
        team_members=state.get("team_members", []),
        lookback_days=state.get("lookback_days", 90),
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "analyze_schedules",
        "stage": OCOStage.EVALUATE_LOAD.value,
        "schedule_analysis": result,
        "reasoning_chain": [
            *chain,
            {
                "step": "analyze_schedules",
                "detail": (f"Members={result.get('member_count')}"),
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "analyze_ms": elapsed,
        },
    }


async def evaluate_load(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Evaluate load distribution."""
    start = time.time()
    tk = _get_toolkit()

    result = await tk.evaluate_load(
        schedule_analysis=state.get(
            "schedule_analysis",
            {},
        ),
    )

    try:
        ctx = _json.dumps(
            {
                "schedule": state.get(
                    "schedule_analysis",
                    {},
                ),
                "load": result,
            },
            default=str,
        )
        llm = await llm_structured(
            system_prompt=SYSTEM_ANALYZE,
            user_prompt=f"Analyze schedule:\n{ctx}",
            schema=AnalyzeOutput,
        )
        if hasattr(llm, "fairness_score"):
            result["llm_fairness"] = llm.fairness_score
        if hasattr(llm, "imbalance_areas"):
            result["llm_imbalances"] = llm.imbalance_areas
    except Exception:
        logger.debug("oco.llm_skipped", node="load")

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "evaluate_load",
        "stage": OCOStage.DETECT_BURNOUT.value,
        "load_evaluation": result,
        "reasoning_chain": [
            *chain,
            {
                "step": "evaluate_load",
                "detail": (f"Fairness={result.get('fairness')}"),
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "load_ms": elapsed,
        },
    }


async def detect_burnout(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Detect burnout risk."""
    start = time.time()
    tk = _get_toolkit()

    assessments = await tk.detect_burnout(
        schedule_analysis=state.get(
            "schedule_analysis",
            {},
        ),
        load_evaluation=state.get(
            "load_evaluation",
            {},
        ),
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    at_risk = sum(
        1
        for a in assessments
        if a.get("burnout_risk")
        in (
            "critical",
            "high",
        )
    )
    return {
        "current_step": "detect_burnout",
        "stage": OCOStage.OPTIMIZE_ROTATION.value,
        "burnout_assessments": assessments,
        "reasoning_chain": [
            *chain,
            {
                "step": "detect_burnout",
                "detail": f"At risk={at_risk}",
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "burnout_ms": elapsed,
        },
    }


async def optimize_rotation(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Optimize the rotation schedule."""
    start = time.time()
    tk = _get_toolkit()

    result = await tk.optimize_rotation(
        schedule_analysis=state.get(
            "schedule_analysis",
            {},
        ),
        burnout_assessments=state.get(
            "burnout_assessments",
            [],
        ),
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "optimize_rotation",
        "stage": OCOStage.RECOMMEND_CHANGES.value,
        "optimized_rotation": result,
        "reasoning_chain": [
            *chain,
            {
                "step": "optimize_rotation",
                "detail": (f"Type={result.get('optimization_type')}"),
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "optimize_ms": elapsed,
        },
    }


async def recommend_changes(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Generate recommendations."""
    start = time.time()
    tk = _get_toolkit()

    recs = await tk.recommend_changes(
        load_evaluation=state.get(
            "load_evaluation",
            {},
        ),
        burnout_assessments=state.get(
            "burnout_assessments",
            [],
        ),
        optimized_rotation=state.get(
            "optimized_rotation",
            {},
        ),
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "recommend_changes",
        "stage": OCOStage.REPORT.value,
        "recommendations": recs,
        "reasoning_chain": [
            *chain,
            {
                "step": "recommend_changes",
                "detail": f"Recs={len(recs)}",
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "recommend_ms": elapsed,
        },
    }


async def report(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Generate optimizer summary report."""
    start = time.time()
    burnouts = state.get("burnout_assessments", [])
    report_data: dict[str, Any] = {
        "team_members": state.get(
            "schedule_analysis",
            {},
        ).get("member_count", 0),
        "fairness": state.get(
            "load_evaluation",
            {},
        ).get("fairness", "unknown"),
        "at_risk_count": sum(
            1
            for b in burnouts
            if b.get("burnout_risk")
            in (
                "critical",
                "high",
            )
        ),
        "recommendations": len(
            state.get("recommendations", []),
        ),
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
            report_data["key_recommendations"] = llm.key_recommendations
    except Exception:
        logger.debug("oco.llm_skipped", node="report")

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "report",
        "stage": OCOStage.REPORT.value,
        "stats": {
            **state.get("stats", {}),
            **report_data,
            "report_ms": elapsed,
        },
        "reasoning_chain": [
            *chain,
            {
                "step": "report",
                "detail": "Optimizer report generated",
                "elapsed_ms": elapsed,
            },
        ],
    }
