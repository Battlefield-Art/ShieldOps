"""Node implementations for the Finding Correlator Agent."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.finding_correlator.models import (
    CorrelatorStage,
    FindingCorrelatorState,
)
from shieldops.agents.finding_correlator.prompts import (
    SYSTEM_CORRELATE,
    SYSTEM_PRIORITIZE,
    SYSTEM_REPORT,
    CorrelationAnalysisOutput,
    CorrelatorReportOutput,
    PrioritizationOutput,
)
from shieldops.agents.finding_correlator.tools import (
    FindingCorrelatorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: FindingCorrelatorToolkit | None = None


def set_toolkit(
    toolkit: FindingCorrelatorToolkit,
) -> None:
    """Set the global toolkit instance."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> FindingCorrelatorToolkit:
    if _toolkit is None:
        return FindingCorrelatorToolkit()
    return _toolkit


async def collect_findings(
    state: FindingCorrelatorState,
) -> dict[str, Any]:
    """Collect raw findings from all sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.collect_findings(
        tenant_id=state.tenant_id,
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "raw_findings": raw,
        "current_stage": (CorrelatorStage.COLLECT_FINDINGS),
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Collected {len(raw)} raw findings ({elapsed}ms)",
        ],
    }


async def normalize_findings(
    state: FindingCorrelatorState,
) -> dict[str, Any]:
    """Normalize findings to common schema."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    normalized = await toolkit.normalize_findings(
        state.raw_findings,
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "normalized": normalized,
        "current_stage": (CorrelatorStage.NORMALIZE_FINDINGS),
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Normalized {len(normalized)} findings ({elapsed}ms)",
        ],
    }


async def deduplicate(
    state: FindingCorrelatorState,
) -> dict[str, Any]:
    """Deduplicate normalized findings."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    deduped, dupes = await toolkit.deduplicate_findings(
        state.normalized,
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "deduplicated": deduped,
        "duplicates_removed": dupes,
        "current_stage": CorrelatorStage.DEDUPLICATE,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Deduplicated: {len(deduped)} unique, {dupes} removed ({elapsed}ms)",
        ],
    }


async def correlate_related(
    state: FindingCorrelatorState,
) -> dict[str, Any]:
    """Correlate related findings."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    groups = await toolkit.correlate_findings(
        state.deduplicated,
    )

    # LLM enrichment for correlation reasoning
    for group in groups:
        finding_titles = []
        for f in state.deduplicated:
            if f.id in group.finding_ids:
                finding_titles.append(f"[{f.severity}] {f.title} on {f.asset}")
        try:
            result = await llm_structured(
                system_prompt=SYSTEM_CORRELATE,
                user_prompt=(
                    "Findings:\n" + "\n".join(finding_titles) + f"\nShared asset: "
                    f"{group.shared_asset}"
                ),
                output_schema=(CorrelationAnalysisOutput),
            )
            group.correlation_reason = result.correlation_reason
            group.combined_risk = result.combined_risk
        except Exception:
            logger.warning(
                "finding_correlator.correlate_fallback",
                group_id=group.id,
            )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "correlations": groups,
        "correlation_groups": len(groups),
        "current_stage": (CorrelatorStage.CORRELATE_RELATED),
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Correlated into {len(groups)} groups ({elapsed}ms)",
        ],
    }


async def prioritize(
    state: FindingCorrelatorState,
) -> dict[str, Any]:
    """Prioritize deduplicated findings."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    prioritized = await toolkit.prioritize_findings(
        state.deduplicated,
        state.correlations,
    )

    # LLM enrichment for action recommendations
    for pf in prioritized[:10]:
        try:
            result = await llm_structured(
                system_prompt=SYSTEM_PRIORITIZE,
                user_prompt=(
                    f"Finding: {pf.title}\n"
                    f"Severity: {pf.severity}\n"
                    f"Risk score: {pf.risk_score}\n"
                    f"Rank: {pf.priority_rank}"
                ),
                output_schema=PrioritizationOutput,
            )
            pf.recommended_action = result.recommended_action
        except Exception:
            logger.warning("finding_correlator.prioritize_fallback")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "prioritized": prioritized,
        "current_stage": CorrelatorStage.PRIORITIZE,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Prioritized {len(prioritized)} findings ({elapsed}ms)",
        ],
    }


async def generate_report(
    state: FindingCorrelatorState,
) -> dict[str, Any]:
    """Generate the correlator report."""
    start = datetime.now(UTC)

    try:
        result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(
                f"Raw findings: "
                f"{len(state.raw_findings)}\n"
                f"After dedup: "
                f"{len(state.deduplicated)}\n"
                f"Duplicates removed: "
                f"{state.duplicates_removed}\n"
                f"Correlation groups: "
                f"{state.correlation_groups}\n"
                f"Prioritized: "
                f"{len(state.prioritized)}"
            ),
            output_schema=CorrelatorReportOutput,
        )
        summary = result.executive_summary
    except Exception:
        logger.warning("finding_correlator.report_fallback")
        summary = (
            f"Correlated {len(state.raw_findings)} "
            f"findings into "
            f"{len(state.deduplicated)} unique, "
            f"{state.duplicates_removed} dupes removed"
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "current_stage": CorrelatorStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Report: {summary[:100]} ({elapsed}ms)",
        ],
        "session_duration_ms": (state.session_duration_ms + elapsed),
    }
