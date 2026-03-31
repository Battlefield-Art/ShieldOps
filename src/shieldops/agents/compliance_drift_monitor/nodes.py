"""Compliance Drift Monitor Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    BaselineComparison,
    CDMStage,
    ControlScan,
    DriftEvent,
    ImpactAssessment,
    ReasoningStep,
)
from .tools import ComplianceDriftMonitorToolkit

logger = structlog.get_logger()

_toolkit: ComplianceDriftMonitorToolkit | None = None  # noqa: PLW0603


def set_toolkit(tk: ComplianceDriftMonitorToolkit) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = tk


def _get_toolkit() -> ComplianceDriftMonitorToolkit:
    assert _toolkit is not None, "Toolkit not initialised"
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Scan Controls
# ------------------------------------------------------------------


async def scan_controls(
    state: dict[str, Any],
    toolkit: ComplianceDriftMonitorToolkit,
) -> dict[str, Any]:
    """Scan current compliance control status."""
    logger.info("cdm.node.scan_controls")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    controls = await toolkit.scan_controls(tenant_id)
    data = [c.model_dump() for c in controls]

    note = f"Scanned {len(controls)} compliance controls"

    return {
        "stage": CDMStage.COMPARE_BASELINE.value,
        "controls": data,
        "total_controls_scanned": len(controls),
        "current_step": "scan_controls",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="scan_controls",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Compare Baseline
# ------------------------------------------------------------------


async def compare_baseline(
    state: dict[str, Any],
    toolkit: ComplianceDriftMonitorToolkit,
) -> dict[str, Any]:
    """Compare current state against baseline."""
    logger.info("cdm.node.compare_baseline")
    state = _to_dict(state)

    controls = [ControlScan(**c) for c in state.get("controls", [])]
    comparisons = await toolkit.compare_baseline(controls)
    data = [c.model_dump() for c in comparisons]

    drifted = sum(1 for c in comparisons if c.has_drifted)
    note = f"Compared {len(comparisons)} controls, {drifted} drifted"

    return {
        "stage": CDMStage.DETECT_DRIFT.value,
        "comparisons": data,
        "current_step": "compare_baseline",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="compare_baseline",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Detect Drift
# ------------------------------------------------------------------


async def detect_drift(
    state: dict[str, Any],
    toolkit: ComplianceDriftMonitorToolkit,
) -> dict[str, Any]:
    """Detect compliance drift from comparisons."""
    logger.info("cdm.node.detect_drift")
    state = _to_dict(state)

    comparisons = [BaselineComparison(**c) for c in state.get("comparisons", [])]
    controls = [ControlScan(**c) for c in state.get("controls", [])]
    drifts = await toolkit.detect_drift(comparisons, controls)
    data = [d.model_dump() for d in drifts]

    note = f"Detected {len(drifts)} drift events"

    try:
        from .prompts import SYSTEM_ANALYZE, DriftInsight

        ctx = json.dumps(
            {
                "drifts": [
                    {
                        "control": d.control_id,
                        "framework": d.framework,
                        "severity": d.severity.value,
                        "type": d.drift_type,
                    }
                    for d in drifts[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            DriftInsight,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"Compliance drifts:\n{ctx}",
                schema=DriftInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cdm",
            node="detect_drift",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cdm",
            node="detect_drift",
        )

    return {
        "stage": CDMStage.ASSESS_IMPACT.value,
        "drift_events": data,
        "drifts_detected": len(drifts),
        "current_step": "detect_drift",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="detect_drift",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Assess Impact
# ------------------------------------------------------------------


async def assess_impact(
    state: dict[str, Any],
    toolkit: ComplianceDriftMonitorToolkit,
) -> dict[str, Any]:
    """Assess impact of compliance drifts."""
    logger.info("cdm.node.assess_impact")
    state = _to_dict(state)

    drifts = [DriftEvent(**d) for d in state.get("drift_events", [])]
    assessments = await toolkit.assess_impact(drifts)
    data = [a.model_dump() for a in assessments]

    high_priority = sum(1 for a in assessments if a.priority <= 2)
    note = f"Assessed {len(assessments)} impacts, {high_priority} high priority"

    return {
        "stage": CDMStage.ALERT.value,
        "impact_assessments": data,
        "current_step": "assess_impact",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="assess_impact",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Alert
# ------------------------------------------------------------------


async def send_alerts(
    state: dict[str, Any],
    toolkit: ComplianceDriftMonitorToolkit,
) -> dict[str, Any]:
    """Send alerts for detected compliance drifts."""
    logger.info("cdm.node.send_alerts")
    state = _to_dict(state)

    drifts = [DriftEvent(**d) for d in state.get("drift_events", [])]
    assessments = [ImpactAssessment(**a) for a in state.get("impact_assessments", [])]
    alerts = await toolkit.send_alerts(drifts, assessments)
    data = [a.model_dump() for a in alerts]

    sent = sum(1 for a in alerts if a.sent)
    note = f"Sent {sent}/{len(alerts)} compliance drift alerts"

    return {
        "stage": CDMStage.REPORT.value,
        "alerts": data,
        "current_step": "send_alerts",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="send_alerts",
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
    toolkit: ComplianceDriftMonitorToolkit,
) -> dict[str, Any]:
    """Compile the final compliance drift report."""
    logger.info("cdm.node.report")
    state = _to_dict(state)

    total_controls = state.get("total_controls_scanned", 0)
    drift_count = state.get("drifts_detected", 0)
    impact_count = len(state.get("impact_assessments", []))
    alert_count = len(state.get("alerts", []))

    lines = [
        "# Compliance Drift Monitor Report",
        "",
        f"**Controls scanned:** {total_controls}",
        f"**Drifts detected:** {drift_count}",
        f"**Impacts assessed:** {impact_count}",
        f"**Alerts sent:** {alert_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "total_controls": total_controls,
                "drifts": drift_count,
                "impacts": impact_count,
                "alerts": alert_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Compliance drift report:\n{ctx}",
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cdm",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cdm",
            node="report",
        )

    return {
        "stage": CDMStage.REPORT.value,
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
