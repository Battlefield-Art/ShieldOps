"""Cloud Cost Anomaly Detector Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    BillingRecord,
    CCADStage,
    CostAnomaly,
    ReasoningStep,
    SpendTrend,
)
from .tools import CloudCostAnomalyDetectorToolkit

logger = structlog.get_logger()

_toolkit: CloudCostAnomalyDetectorToolkit | None = None  # noqa: PLW0603


def set_toolkit(tk: CloudCostAnomalyDetectorToolkit) -> None:  # noqa: PLW0603
    """Set the module-level toolkit."""
    global _toolkit  # noqa: PLW0603
    _toolkit = tk


def _get_toolkit() -> CloudCostAnomalyDetectorToolkit:
    if _toolkit is None:
        msg = "Toolkit not initialised — call set_toolkit first"
        raise RuntimeError(msg)
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Collect Billing
# ------------------------------------------------------------------


async def collect_billing(
    state: dict[str, Any],
    toolkit: CloudCostAnomalyDetectorToolkit,
) -> dict[str, Any]:
    """Collect billing records from cloud providers."""
    logger.info("ccad.node.collect_billing")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    records = await toolkit.collect_billing(tenant_id)
    data = [r.model_dump() for r in records]
    total = sum(r.cost_usd for r in records)

    note = f"Collected {len(records)} billing records, total ${total:.2f}"

    return {
        "stage": CCADStage.ANALYZE_TRENDS.value,
        "billing_records": data,
        "total_spend_analyzed": round(total, 2),
        "current_step": "collect_billing",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="collect_billing",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Analyze Trends
# ------------------------------------------------------------------


async def analyze_trends(
    state: dict[str, Any],
    toolkit: CloudCostAnomalyDetectorToolkit,
) -> dict[str, Any]:
    """Analyze spending trends per service."""
    logger.info("ccad.node.analyze_trends")
    state = _to_dict(state)

    records = [BillingRecord(**r) for r in state.get("billing_records", [])]
    trends = await toolkit.analyze_trends(records)
    data = [t.model_dump() for t in trends]

    note = f"Identified {len(trends)} spend trends"

    try:
        from .prompts import SYSTEM_ANALYZE, TrendInsight

        ctx = json.dumps(
            {
                "trends": [
                    {
                        "service": t.service,
                        "provider": t.provider.value,
                        "change_pct": t.change_pct,
                        "daily_cost": t.current_daily_cost,
                    }
                    for t in trends[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            TrendInsight,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"Spend trends:\n{ctx}",
                schema=TrendInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="ccad",
            node="analyze_trends",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="ccad",
            node="analyze_trends",
        )

    return {
        "stage": CCADStage.DETECT_ANOMALIES.value,
        "spend_trends": data,
        "current_step": "analyze_trends",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="analyze_trends",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Detect Anomalies
# ------------------------------------------------------------------


async def detect_anomalies(
    state: dict[str, Any],
    toolkit: CloudCostAnomalyDetectorToolkit,
) -> dict[str, Any]:
    """Detect cost anomalies from trends."""
    logger.info("ccad.node.detect_anomalies")
    state = _to_dict(state)

    trends = [SpendTrend(**t) for t in state.get("spend_trends", [])]
    anomalies = await toolkit.detect_anomalies(trends)
    data = [a.model_dump() for a in anomalies]

    note = f"Detected {len(anomalies)} anomalies across {len(trends)} trends"

    return {
        "stage": CCADStage.CLASSIFY_CAUSE.value,
        "anomalies": data,
        "anomalies_detected": len(anomalies),
        "current_step": "detect_anomalies",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="detect_anomalies",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Classify Cause
# ------------------------------------------------------------------


async def classify_cause(
    state: dict[str, Any],
    toolkit: CloudCostAnomalyDetectorToolkit,
) -> dict[str, Any]:
    """Classify root causes for anomalies."""
    logger.info("ccad.node.classify_cause")
    state = _to_dict(state)

    anomalies = [CostAnomaly(**a) for a in state.get("anomalies", [])]
    classifications = await toolkit.classify_cause(anomalies)
    data = [c.model_dump() for c in classifications]

    remediable = sum(1 for c in classifications if c.auto_remediable)
    note = f"Classified {len(classifications)} causes, {remediable} auto-remediable"

    return {
        "stage": CCADStage.ALERT.value,
        "classifications": data,
        "current_step": "classify_cause",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="classify_cause",
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
    toolkit: CloudCostAnomalyDetectorToolkit,
) -> dict[str, Any]:
    """Send alerts for detected anomalies."""
    logger.info("ccad.node.send_alerts")
    state = _to_dict(state)

    anomalies = [CostAnomaly(**a) for a in state.get("anomalies", [])]
    alerts = await toolkit.send_alerts(anomalies)
    data = [a.model_dump() for a in alerts]

    sent_count = sum(1 for a in alerts if a.status == "sent")
    note = f"Sent {sent_count}/{len(alerts)} alerts"

    return {
        "stage": CCADStage.REPORT.value,
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
    toolkit: CloudCostAnomalyDetectorToolkit,
) -> dict[str, Any]:
    """Compile the final cost anomaly report."""
    logger.info("ccad.node.report")
    state = _to_dict(state)

    total_spend = state.get("total_spend_analyzed", 0.0)
    anomaly_count = state.get("anomalies_detected", 0)
    class_count = len(state.get("classifications", []))
    alert_count = len(state.get("alerts", []))

    lines = [
        "# Cloud Cost Anomaly Report",
        "",
        f"**Total spend analyzed:** ${total_spend:,.2f}",
        f"**Anomalies detected:** {anomaly_count}",
        f"**Causes classified:** {class_count}",
        f"**Alerts sent:** {alert_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "total_spend": total_spend,
                "anomalies": anomaly_count,
                "classifications": class_count,
                "alerts": alert_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Cost anomaly report:\n{ctx}",
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="ccad",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="ccad",
            node="report",
        )

    return {
        "stage": CCADStage.REPORT.value,
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
