"""Node implementations for the Continuous Scanner Agent."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.continuous_scanner.models import (
    ContinuousScannerState,
    SchedulerStage,
)
from shieldops.agents.continuous_scanner.prompts import (
    SYSTEM_ANALYZE,
    SYSTEM_REPORT,
    SYSTEM_SCHEDULE,
    ScannerReportOutput,
    ScanResultAnalysisOutput,
    ScheduleOptimizationOutput,
)
from shieldops.agents.continuous_scanner.tools import (
    ContinuousScannerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ContinuousScannerToolkit | None = None


def _get_toolkit() -> ContinuousScannerToolkit:
    if _toolkit is None:
        return ContinuousScannerToolkit()
    return _toolkit


async def load_schedule(
    state: ContinuousScannerState,
) -> dict[str, Any]:
    """Load scan schedules."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    schedules = await toolkit.load_schedules(
        tenant_id=state.tenant_id,
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "schedules": schedules,
        "current_stage": SchedulerStage.LOAD_SCHEDULE,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Loaded {len(schedules)} schedules ({elapsed}ms)",
        ],
    }


async def check_due_scans(
    state: ContinuousScannerState,
) -> dict[str, Any]:
    """Check which scans are due."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    due = await toolkit.check_due_scans(
        state.schedules,
    )

    # LLM optimization of schedule priorities
    for scan in due:
        try:
            result = await llm_structured(
                system_prompt=SYSTEM_SCHEDULE,
                user_prompt=(
                    f"Scan type: {scan.scan_type}\n"
                    f"Agent: {scan.agent_name}\n"
                    f"Assets: "
                    f"{', '.join(scan.target_assets)}\n"
                    f"Overdue: {scan.overdue_minutes}m"
                ),
                schema=(ScheduleOptimizationOutput),
            )
            scan.priority = result.priority  # type: ignore[union-attr]
        except Exception:
            logger.warning("continuous_scanner.schedule_fallback")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "due_scans": due,
        "current_stage": (SchedulerStage.CHECK_DUE_SCANS),
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Found {len(due)} due scans ({elapsed}ms)",
        ],
    }


async def dispatch_scans(
    state: ContinuousScannerState,
) -> dict[str, Any]:
    """Dispatch due scans to agents."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    dispatched = await toolkit.dispatch_scans(
        state.due_scans,
        state.tenant_id,
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "dispatched": dispatched,
        "scans_run_today": (state.scans_run_today + len(dispatched)),
        "current_stage": (SchedulerStage.DISPATCH_SCANS),
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Dispatched {len(dispatched)} scans ({elapsed}ms)",
        ],
    }


async def monitor_progress(
    state: ContinuousScannerState,
) -> dict[str, Any]:
    """Monitor scan progress."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    progress = await toolkit.monitor_progress(
        state.dispatched,
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "in_progress": progress,
        "current_stage": (SchedulerStage.MONITOR_PROGRESS),
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Monitoring {len(progress)} scans ({elapsed}ms)",
        ],
    }


async def collect_results(
    state: ContinuousScannerState,
) -> dict[str, Any]:
    """Collect scan results."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.collect_results(
        state.in_progress,
    )

    # LLM analysis of results
    try:
        summaries = [
            f"{r.agent_name}: {r.findings_count} findings ({r.critical_count} critical)"
            for r in results
        ]
        result_analysis = await llm_structured(
            system_prompt=SYSTEM_ANALYZE,
            user_prompt=("Scan results:\n" + "\n".join(summaries)),
            schema=ScanResultAnalysisOutput,
        )
        _ = result_analysis.risk_trend  # type: ignore[union-attr]
    except Exception:
        logger.warning("continuous_scanner.analysis_fallback")

    total_assets = sum(len(s.target_assets) for s in state.schedules)
    covered = sum(1 for r in results if r.status == "completed")
    coverage = round((covered / max(total_assets, 1)) * 100, 1)

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "completed": results,
        "coverage_pct": coverage,
        "current_stage": (SchedulerStage.COLLECT_RESULTS),
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Collected {len(results)} results, coverage {coverage}% ({elapsed}ms)",
        ],
    }


async def generate_report(
    state: ContinuousScannerState,
) -> dict[str, Any]:
    """Generate scanner report."""
    start = datetime.now(UTC)

    try:
        result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(
                f"Scans today: "
                f"{state.scans_run_today}\n"
                f"Coverage: {state.coverage_pct}%\n"
                f"Completed: {len(state.completed)}\n"
                f"Schedules: {len(state.schedules)}"
            ),
            schema=ScannerReportOutput,
        )
        summary = result.executive_summary  # type: ignore[union-attr]
    except Exception:
        logger.warning("continuous_scanner.report_fallback")
        summary = f"Ran {state.scans_run_today} scans, coverage {state.coverage_pct}%"

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "current_stage": SchedulerStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Report: {summary[:100]} ({elapsed}ms)",
        ],
        "session_duration_ms": (state.session_duration_ms + elapsed),
    }
