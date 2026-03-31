"""Alert Fatigue Reducer Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    AFRStage,
    AlertRecord,
    NoiseAnalysis,
    ReasoningStep,
    TuningRule,
)
from .tools import AlertFatigueReducerToolkit

logger = structlog.get_logger()

_toolkit: AlertFatigueReducerToolkit | None = None  # noqa: PLW0603


def set_toolkit(tk: AlertFatigueReducerToolkit) -> None:
    """Set the module-level toolkit."""
    global _toolkit  # noqa: PLW0603
    _toolkit = tk


def _get_toolkit() -> AlertFatigueReducerToolkit:
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
# Node 1: Collect Alerts
# ------------------------------------------------------------------


async def collect_alerts(
    state: dict[str, Any],
    toolkit: AlertFatigueReducerToolkit,
) -> dict[str, Any]:
    """Collect alert data from SIEM/SOAR."""
    logger.info("afr.node.collect_alerts")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    alerts = await toolkit.collect_alerts(tenant_id)
    data = [a.model_dump() for a in alerts]

    note = f"Collected {len(alerts)} alert rules for analysis"

    return {
        "stage": AFRStage.ANALYZE_NOISE.value,
        "alerts": data,
        "total_alerts_analyzed": sum(a.count_24h for a in alerts),
        "current_step": "collect_alerts",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="collect_alerts",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Analyze Noise
# ------------------------------------------------------------------


async def analyze_noise(
    state: dict[str, Any],
    toolkit: AlertFatigueReducerToolkit,
) -> dict[str, Any]:
    """Analyze alert noise per rule."""
    logger.info("afr.node.analyze_noise")
    state = _to_dict(state)

    alerts = [AlertRecord(**a) for a in state.get("alerts", [])]
    analyses = await toolkit.analyze_noise(alerts)
    data = [a.model_dump() for a in analyses]

    noisy = sum(1 for a in analyses if a.noise_score > 0.5)
    note = f"Analyzed {len(analyses)} rules, {noisy} noisy"

    try:
        from .prompts import SYSTEM_ANALYZE, NoiseInsight

        ctx = json.dumps(
            {
                "analyses": [
                    {
                        "rule_id": a.rule_id,
                        "noise_score": a.noise_score,
                        "category": a.noise_category.value,
                        "signal_ratio": a.signal_ratio,
                    }
                    for a in analyses[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            NoiseInsight,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"Alert noise data:\n{ctx}",
                schema=NoiseInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="afr",
            node="analyze_noise",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="afr",
            node="analyze_noise",
        )

    return {
        "stage": AFRStage.DETECT_FATIGUE.value,
        "noise_analyses": data,
        "current_step": "analyze_noise",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="analyze_noise",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Detect Fatigue
# ------------------------------------------------------------------


async def detect_fatigue(
    state: dict[str, Any],
    toolkit: AlertFatigueReducerToolkit,
) -> dict[str, Any]:
    """Detect analyst fatigue indicators."""
    logger.info("afr.node.detect_fatigue")
    state = _to_dict(state)

    alerts = [AlertRecord(**a) for a in state.get("alerts", [])]
    indicators = await toolkit.detect_fatigue(alerts)
    data = [f.model_dump() for f in indicators]

    at_risk = sum(1 for f in indicators if f.burnout_risk == "high")
    note = f"Assessed {len(indicators)} analysts, {at_risk} at high burnout risk"

    return {
        "stage": AFRStage.TUNE_RULES.value,
        "fatigue_indicators": data,
        "current_step": "detect_fatigue",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="detect_fatigue",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Tune Rules
# ------------------------------------------------------------------


async def tune_rules(
    state: dict[str, Any],
    toolkit: AlertFatigueReducerToolkit,
) -> dict[str, Any]:
    """Generate rule tuning suggestions."""
    logger.info("afr.node.tune_rules")
    state = _to_dict(state)

    analyses = [NoiseAnalysis(**a) for a in state.get("noise_analyses", [])]
    tunings = await toolkit.tune_rules(analyses)
    data = [t.model_dump() for t in tunings]

    note = f"Generated {len(tunings)} tuning suggestions"

    return {
        "stage": AFRStage.VALIDATE.value,
        "tuning_rules": data,
        "current_step": "tune_rules",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="tune_rules",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Validate
# ------------------------------------------------------------------


async def validate_changes(
    state: dict[str, Any],
    toolkit: AlertFatigueReducerToolkit,
) -> dict[str, Any]:
    """Validate proposed tuning changes."""
    logger.info("afr.node.validate")
    state = _to_dict(state)

    tunings = [TuningRule(**t) for t in state.get("tuning_rules", [])]
    validations = await toolkit.validate_changes(tunings)
    data = [v.model_dump() for v in validations]

    safe = sum(1 for v in validations if v.safe_to_deploy)
    avg_reduction = (
        sum(v.reduction_pct for v in validations) / len(validations) if validations else 0.0
    )
    note = f"Validated {len(validations)} tunings, {safe} safe to deploy"

    return {
        "stage": AFRStage.REPORT.value,
        "validations": data,
        "noise_reduction_pct": round(avg_reduction, 1),
        "current_step": "validate",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="validate",
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
    toolkit: AlertFatigueReducerToolkit,
) -> dict[str, Any]:
    """Compile the final alert fatigue report."""
    logger.info("afr.node.report")
    state = _to_dict(state)

    total_alerts = state.get("total_alerts_analyzed", 0)
    reduction = state.get("noise_reduction_pct", 0.0)
    tuning_count = len(state.get("tuning_rules", []))
    validation_count = len(state.get("validations", []))

    lines = [
        "# Alert Fatigue Reduction Report",
        "",
        f"**Total alerts analyzed (24h):** {total_alerts}",
        f"**Noise reduction:** {reduction}%",
        f"**Tuning suggestions:** {tuning_count}",
        f"**Validations passed:** {validation_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "total_alerts": total_alerts,
                "noise_reduction": reduction,
                "tunings": tuning_count,
                "validations": validation_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Alert fatigue report:\n{ctx}",
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="afr",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="afr",
            node="report",
        )

    return {
        "stage": AFRStage.REPORT.value,
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
