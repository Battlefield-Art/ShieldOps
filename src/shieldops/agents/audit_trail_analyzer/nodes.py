"""Audit Trail Analyzer Agent — Node implementations."""

from __future__ import annotations

from typing import Any

import structlog
from pydantic import BaseModel, Field

from shieldops.utils.llm import llm_structured

from .models import ATAStage
from .tools import AuditTrailAnalyzerToolkit

logger = structlog.get_logger()

_toolkit: AuditTrailAnalyzerToolkit | None = None


def set_toolkit(
    toolkit: AuditTrailAnalyzerToolkit,
) -> None:
    """Configure the module-level toolkit."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> AuditTrailAnalyzerToolkit:
    if _toolkit is None:
        return AuditTrailAnalyzerToolkit()
    return _toolkit


class _LLMAuditInsight(BaseModel):
    """LLM-generated audit analysis insight."""

    threat_indicators: list[str] = Field(
        description="Indicators of compromise found",
    )
    attack_patterns: list[str] = Field(
        description="Attack patterns identified",
    )
    risk_summary: str = Field(
        description="Overall audit trail risk summary",
    )


async def collect_logs(
    state: dict[str, Any],
    toolkit: AuditTrailAnalyzerToolkit,
) -> dict[str, Any]:
    """Collect audit logs from all sources."""
    logger.info("ata.node.collect_logs")

    tenant_id = state.get("tenant_id", "default")
    sources = state.get("sources")
    events = await toolkit.collect_logs(
        tenant_id,
        sources,
    )

    return {
        "stage": ATAStage.NORMALIZE_EVENTS.value,
        "events": events,
        "total_events": len(events),
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [f"Collected {len(events)} audit events"],
    }


async def normalize_events(
    state: dict[str, Any],
    toolkit: AuditTrailAnalyzerToolkit,
) -> dict[str, Any]:
    """Normalize collected audit events."""
    logger.info("ata.node.normalize_events")
    events = state.get("events", [])

    normalized: list[dict[str, Any]] = []
    for event in events:
        result = toolkit.normalize_event(event)
        normalized.append(result)

    return {
        "stage": ATAStage.DETECT_ANOMALIES.value,
        "events": normalized,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [f"Normalized {len(normalized)} events"],
    }


async def detect_anomalies(
    state: dict[str, Any],
    toolkit: AuditTrailAnalyzerToolkit,
) -> dict[str, Any]:
    """Detect anomalies in audit events."""
    logger.info("ata.node.detect_anomalies")
    events = state.get("events", [])

    anomalies = toolkit.detect_anomalies(events)

    llm_note = ""
    try:
        summary = "\n".join(
            f"- {a.get('anomaly_type')}: {a.get('description')} [{a.get('severity')}]"
            for a in anomalies[:15]
        )
        result = await llm_structured(
            system_prompt=(
                "You are a security analyst examining "
                "audit trail anomalies. Identify attack "
                "patterns and indicators of compromise."
            ),
            user_prompt=(f"Detected anomalies:\n{summary}\n\nTotal events analyzed: {len(events)}"),
            schema=_LLMAuditInsight,
        )
        if isinstance(result, _LLMAuditInsight):
            llm_note = f" LLM: {result.risk_summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="ata",
            node="detect_anomalies",
        )

    note = f"Detected {len(anomalies)} anomalies"
    return {
        "stage": ATAStage.CORRELATE_ACTIVITIES.value,
        "anomalies": anomalies,
        "anomalies_detected": len(anomalies),
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [note + llm_note],
    }


async def correlate_activities(
    state: dict[str, Any],
    toolkit: AuditTrailAnalyzerToolkit,
) -> dict[str, Any]:
    """Correlate anomalies into findings."""
    logger.info("ata.node.correlate_activities")
    anomalies = state.get("anomalies", [])
    events = state.get("events", [])

    findings = toolkit.correlate_activities(
        anomalies,
        events,
    )

    return {
        "stage": ATAStage.GENERATE_FINDINGS.value,
        "findings": findings,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [f"Correlated {len(anomalies)} anomalies into {len(findings)} findings"],
    }


async def generate_findings(
    state: dict[str, Any],
    toolkit: AuditTrailAnalyzerToolkit,
) -> dict[str, Any]:
    """Generate and classify findings."""
    logger.info("ata.node.generate_findings")
    findings = state.get("findings", [])

    critical = sum(1 for f in findings if f.get("severity") == "critical")

    return {
        "stage": ATAStage.REPORT.value,
        "critical_findings": critical,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [f"Generated {len(findings)} findings, {critical} critical"],
    }


async def report(
    state: dict[str, Any],
    toolkit: AuditTrailAnalyzerToolkit,
) -> dict[str, Any]:
    """Generate audit trail analysis report."""
    logger.info("ata.node.report")

    rpt = toolkit.generate_report(
        events=state.get("events", []),
        anomalies=state.get("anomalies", []),
        findings=state.get("findings", []),
    )

    return {
        "stage": ATAStage.REPORT.value,
        "report": rpt,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            f"Report: {rpt.get('anomalies_detected')} "
            f"anomalies, {rpt.get('total_findings')} "
            f"findings"
        ],
    }
