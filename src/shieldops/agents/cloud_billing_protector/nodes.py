"""Cloud Billing Protector Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    BillingAnomaly,
    BillingRecord,
    CBPStage,
    FraudClassification,
    ReasoningStep,
    SpendPattern,
)
from .tools import CloudBillingProtectorToolkit

logger = structlog.get_logger()

_toolkit: CloudBillingProtectorToolkit | None = None  # noqa: PLW0603


def set_toolkit(tk: CloudBillingProtectorToolkit) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = tk


def _get_toolkit() -> CloudBillingProtectorToolkit:
    if _toolkit is None:
        msg = "Toolkit not initialized"
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
    toolkit: CloudBillingProtectorToolkit,
) -> dict[str, Any]:
    """Collect billing records from cloud providers."""
    logger.info("cbp.node.collect_billing")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    records = await toolkit.collect_billing(tenant_id)
    data = [r.model_dump() for r in records]

    total = sum(r.cost_usd for r in records)
    note = f"Collected {len(records)} billing records, total ${total:.2f}"

    return {
        "stage": CBPStage.ANALYZE_PATTERNS.value,
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
# Node 2: Analyze Patterns
# ------------------------------------------------------------------


async def analyze_patterns(
    state: dict[str, Any],
    toolkit: CloudBillingProtectorToolkit,
) -> dict[str, Any]:
    """Analyze spending patterns."""
    logger.info("cbp.node.analyze_patterns")
    state = _to_dict(state)

    records = [BillingRecord(**r) for r in state.get("billing_records", [])]
    patterns = await toolkit.analyze_patterns(records)
    data = [p.model_dump() for p in patterns]

    spikes = sum(1 for p in patterns if p.trend == "spike")
    note = f"Analyzed {len(patterns)} spend patterns, {spikes} spikes"

    try:
        from .prompts import SYSTEM_ANALYZE, PatternInsight

        ctx = json.dumps(
            {
                "patterns": [
                    {
                        "service": p.service,
                        "deviation": p.deviation_pct,
                        "trend": p.trend,
                        "daily_cost": p.current_daily_cost,
                    }
                    for p in patterns[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            PatternInsight,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"Billing patterns:\n{ctx}",
                schema=PatternInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cbp",
            node="analyze_patterns",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cbp",
            node="analyze_patterns",
        )

    return {
        "stage": CBPStage.DETECT_ANOMALIES.value,
        "patterns": data,
        "current_step": "analyze_patterns",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="analyze_patterns",
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
    toolkit: CloudBillingProtectorToolkit,
) -> dict[str, Any]:
    """Detect billing anomalies."""
    logger.info("cbp.node.detect_anomalies")
    state = _to_dict(state)

    records = [BillingRecord(**r) for r in state.get("billing_records", [])]
    patterns = [SpendPattern(**p) for p in state.get("patterns", [])]
    anomalies = await toolkit.detect_billing_anomalies(records, patterns)
    data = [a.model_dump() for a in anomalies]

    total_excess = sum(a.excess_cost for a in anomalies)
    note = f"Detected {len(anomalies)} anomalies, excess cost ${total_excess:.2f}"

    return {
        "stage": CBPStage.CLASSIFY_FRAUD.value,
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
# Node 4: Classify Fraud
# ------------------------------------------------------------------


async def classify_fraud(
    state: dict[str, Any],
    toolkit: CloudBillingProtectorToolkit,
) -> dict[str, Any]:
    """Classify anomalies as potential fraud."""
    logger.info("cbp.node.classify_fraud")
    state = _to_dict(state)

    anomalies = [BillingAnomaly(**a) for a in state.get("anomalies", [])]
    records = [BillingRecord(**r) for r in state.get("billing_records", [])]
    classifications = await toolkit.classify_fraud(anomalies, records)
    data = [c.model_dump() for c in classifications]

    confirmed = sum(1 for c in classifications if c.is_confirmed)
    note = f"Classified {len(classifications)} anomalies, {confirmed} confirmed fraud"

    return {
        "stage": CBPStage.ENFORCE_LIMITS.value,
        "fraud_classifications": data,
        "current_step": "classify_fraud",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="classify_fraud",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Enforce Limits
# ------------------------------------------------------------------


async def enforce_limits(
    state: dict[str, Any],
    toolkit: CloudBillingProtectorToolkit,
) -> dict[str, Any]:
    """Enforce budget limits and terminate rogue resources."""
    logger.info("cbp.node.enforce_limits")
    state = _to_dict(state)

    anomalies = [BillingAnomaly(**a) for a in state.get("anomalies", [])]
    classifications = [FraudClassification(**c) for c in state.get("fraud_classifications", [])]
    enforcements = await toolkit.enforce_limits(anomalies, classifications)
    data = [e.model_dump() for e in enforcements]

    terminated = sum(1 for e in enforcements if e.auto_terminated)
    note = f"Enforced {len(enforcements)} actions, {terminated} auto-terminated"

    return {
        "stage": CBPStage.REPORT.value,
        "enforcements": data,
        "current_step": "enforce_limits",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="enforce_limits",
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
    toolkit: CloudBillingProtectorToolkit,
) -> dict[str, Any]:
    """Compile the final billing protection report."""
    logger.info("cbp.node.report")
    state = _to_dict(state)

    total_spend = state.get("total_spend_analyzed", 0.0)
    anomaly_count = state.get("anomalies_detected", 0)
    enforce_count = len(state.get("enforcements", []))

    lines = [
        "# Cloud Billing Protection Report",
        "",
        f"**Total spend analyzed:** ${total_spend:.2f}",
        f"**Anomalies detected:** {anomaly_count}",
        f"**Enforcement actions:** {enforce_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "total_spend": total_spend,
                "anomalies": anomaly_count,
                "enforcements": enforce_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Billing protection report:\n{ctx}",
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cbp",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cbp",
            node="report",
        )

    return {
        "stage": CBPStage.REPORT.value,
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
