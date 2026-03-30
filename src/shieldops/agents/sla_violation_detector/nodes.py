"""Node implementations for the SLA Violation Detector."""

from __future__ import annotations

import json as _json
import time
from typing import Any

import structlog

from shieldops.utils.llm import llm_structured

from .models import SVDStage
from .prompts import (
    SYSTEM_ANALYZE,
    SYSTEM_REPORT,
    AnalyzeOutput,
    ReportOutput,
)
from .tools import SLAViolationDetectorToolkit

logger = structlog.get_logger()

_toolkit: SLAViolationDetectorToolkit | None = None


def set_toolkit(
    toolkit: SLAViolationDetectorToolkit,
) -> None:
    """Set the shared toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SLAViolationDetectorToolkit:
    if _toolkit is None:
        return SLAViolationDetectorToolkit()
    return _toolkit


async def collect_metrics(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Collect SLA metrics."""
    start = time.time()
    tk = _get_toolkit()

    metrics = await tk.collect_metrics(
        services=state.get("services", []),
        time_window_hours=state.get(
            "time_window_hours",
            24,
        ),
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "collect_metrics",
        "stage": SVDStage.EVALUATE_THRESHOLDS.value,
        "collected_metrics": metrics,
        "reasoning_chain": [
            *chain,
            {
                "step": "collect_metrics",
                "detail": f"Metrics={len(metrics)}",
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "collect_ms": elapsed,
        },
    }


async def evaluate_thresholds(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Evaluate metrics against thresholds."""
    start = time.time()
    tk = _get_toolkit()

    evals = await tk.evaluate_thresholds(
        collected_metrics=state.get(
            "collected_metrics",
            [],
        ),
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "evaluate_thresholds",
        "stage": SVDStage.DETECT_VIOLATIONS.value,
        "threshold_evaluations": evals,
        "reasoning_chain": [
            *chain,
            {
                "step": "evaluate_thresholds",
                "detail": f"Evaluated={len(evals)}",
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "evaluate_ms": elapsed,
        },
    }


async def detect_violations(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Detect active SLA violations."""
    start = time.time()
    tk = _get_toolkit()

    violations = await tk.detect_violations(
        threshold_evaluations=state.get(
            "threshold_evaluations",
            [],
        ),
    )

    try:
        ctx = _json.dumps(
            {
                "violations": violations[:10],
                "total_evaluations": len(
                    state.get("threshold_evaluations", []),
                ),
            },
            default=str,
        )
        llm = await llm_structured(
            system_prompt=SYSTEM_ANALYZE,
            user_prompt=f"Analyze violations:\n{ctx}",
            schema=AnalyzeOutput,
        )
        if hasattr(llm, "risk_level"):
            for v in violations:
                v["llm_risk"] = llm.risk_level
    except Exception:
        logger.debug("svd.llm_skipped", node="detect")

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "detect_violations",
        "stage": SVDStage.CALCULATE_IMPACT.value,
        "violations": violations,
        "reasoning_chain": [
            *chain,
            {
                "step": "detect_violations",
                "detail": (f"Violations={len(violations)}"),
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "detect_ms": elapsed,
        },
    }


async def calculate_impact(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Calculate business impact."""
    start = time.time()
    tk = _get_toolkit()

    impacts = await tk.calculate_impact(
        violations=state.get("violations", []),
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "calculate_impact",
        "stage": SVDStage.NOTIFY_OWNERS.value,
        "impact_calculations": impacts,
        "reasoning_chain": [
            *chain,
            {
                "step": "calculate_impact",
                "detail": f"Impacts={len(impacts)}",
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "impact_ms": elapsed,
        },
    }


async def notify_owners(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Notify service owners."""
    start = time.time()
    tk = _get_toolkit()

    notes = await tk.notify_owners(
        violations=state.get("violations", []),
        impact_calculations=state.get(
            "impact_calculations",
            [],
        ),
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "notify_owners",
        "stage": SVDStage.REPORT.value,
        "notifications": notes,
        "reasoning_chain": [
            *chain,
            {
                "step": "notify_owners",
                "detail": f"Notified={len(notes)}",
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "notify_ms": elapsed,
        },
    }


async def report(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Generate SLA violation report."""
    start = time.time()
    violations = state.get("violations", [])
    impacts = state.get("impact_calculations", [])
    report_data: dict[str, Any] = {
        "total_metrics": len(
            state.get("collected_metrics", []),
        ),
        "total_violations": len(violations),
        "breaches": sum(1 for v in violations if v.get("status") == "breach"),
        "warnings": sum(1 for v in violations if v.get("status") == "warning"),
        "total_cost_usd": sum(i.get("estimated_cost_usd", 0) for i in impacts),
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
            report_data["remediation_plan"] = llm.remediation_plan
    except Exception:
        logger.debug("svd.llm_skipped", node="report")

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "report",
        "stage": SVDStage.REPORT.value,
        "stats": {
            **state.get("stats", {}),
            **report_data,
            "report_ms": elapsed,
        },
        "reasoning_chain": [
            *chain,
            {
                "step": "report",
                "detail": "SLA violation report generated",
                "elapsed_ms": elapsed,
            },
        ],
    }
