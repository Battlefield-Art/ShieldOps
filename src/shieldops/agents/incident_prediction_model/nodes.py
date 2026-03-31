"""Incident Prediction Model Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    ConfidenceAssessment,
    FeatureVector,
    IPMStage,
    LeadingIndicator,
    PredictionResult,
    ReasoningStep,
)
from .tools import IncidentPredictionModelToolkit

logger = structlog.get_logger()

_toolkit: IncidentPredictionModelToolkit | None = None  # noqa: PLW0603


def set_toolkit(tk: IncidentPredictionModelToolkit) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = tk


def _get_toolkit() -> IncidentPredictionModelToolkit:
    assert _toolkit is not None, "Toolkit not initialised"
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Collect Indicators
# ------------------------------------------------------------------


async def collect_indicators(
    state: dict[str, Any],
    toolkit: IncidentPredictionModelToolkit,
) -> dict[str, Any]:
    """Collect leading indicators from telemetry."""
    logger.info("ipm.node.collect_indicators")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    indicators = await toolkit.collect_indicators(tenant_id)
    data = [ind.model_dump() for ind in indicators]

    note = f"Collected {len(indicators)} leading indicators"

    return {
        "stage": IPMStage.EXTRACT_FEATURES.value,
        "indicators": data,
        "total_indicators": len(indicators),
        "current_step": "collect_indicators",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="collect_indicators",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Extract Features
# ------------------------------------------------------------------


async def extract_features(
    state: dict[str, Any],
    toolkit: IncidentPredictionModelToolkit,
) -> dict[str, Any]:
    """Extract feature vectors from indicators."""
    logger.info("ipm.node.extract_features")
    state = _to_dict(state)

    indicators = [LeadingIndicator(**ind) for ind in state.get("indicators", [])]
    vectors = await toolkit.extract_features(indicators)
    data = [v.model_dump() for v in vectors]

    note = f"Extracted {len(vectors)} feature vectors"

    return {
        "stage": IPMStage.RUN_MODEL.value,
        "feature_vectors": data,
        "current_step": "extract_features",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="extract_features",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Run Model
# ------------------------------------------------------------------


async def run_model(
    state: dict[str, Any],
    toolkit: IncidentPredictionModelToolkit,
) -> dict[str, Any]:
    """Run the prediction model on feature vectors."""
    logger.info("ipm.node.run_model")
    state = _to_dict(state)

    vectors = [FeatureVector(**fv) for fv in state.get("feature_vectors", [])]
    predictions = await toolkit.run_prediction_model(vectors)
    data = [p.model_dump() for p in predictions]

    note = f"Generated {len(predictions)} predictions"

    try:
        from .prompts import SYSTEM_ANALYZE, PredictionInsight

        ctx = json.dumps(
            {
                "predictions": [
                    {
                        "type": p.incident_type,
                        "probability": p.probability,
                        "risk": p.risk_level.value,
                        "horizon_h": p.time_horizon_hours,
                    }
                    for p in predictions[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            PredictionInsight,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"Incident predictions:\n{ctx}",
                schema=PredictionInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="ipm",
            node="run_model",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="ipm",
            node="run_model",
        )

    return {
        "stage": IPMStage.ASSESS_CONFIDENCE.value,
        "predictions": data,
        "predictions_generated": len(predictions),
        "current_step": "run_model",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="run_model",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Assess Confidence
# ------------------------------------------------------------------


async def assess_confidence(
    state: dict[str, Any],
    toolkit: IncidentPredictionModelToolkit,
) -> dict[str, Any]:
    """Assess confidence of predictions."""
    logger.info("ipm.node.assess_confidence")
    state = _to_dict(state)

    predictions = [PredictionResult(**p) for p in state.get("predictions", [])]
    vectors = [FeatureVector(**fv) for fv in state.get("feature_vectors", [])]
    assessments = await toolkit.assess_confidence(predictions, vectors)
    data = [a.model_dump() for a in assessments]

    high_conf = sum(1 for a in assessments if a.overall_confidence > 0.7)
    note = f"Assessed {len(assessments)} predictions, {high_conf} high confidence"

    return {
        "stage": IPMStage.GENERATE_WARNINGS.value,
        "confidence_assessments": data,
        "current_step": "assess_confidence",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="assess_confidence",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Generate Warnings
# ------------------------------------------------------------------


async def generate_warnings(
    state: dict[str, Any],
    toolkit: IncidentPredictionModelToolkit,
) -> dict[str, Any]:
    """Generate early warnings from predictions."""
    logger.info("ipm.node.generate_warnings")
    state = _to_dict(state)

    predictions = [PredictionResult(**p) for p in state.get("predictions", [])]
    assessments = [ConfidenceAssessment(**a) for a in state.get("confidence_assessments", [])]
    warnings = await toolkit.generate_warnings(predictions, assessments)
    data = [w.model_dump() for w in warnings]

    critical = sum(1 for w in warnings if w.severity == "critical")
    note = f"Generated {len(warnings)} warnings, {critical} critical"

    return {
        "stage": IPMStage.REPORT.value,
        "warnings": data,
        "current_step": "generate_warnings",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="generate_warnings",
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
    toolkit: IncidentPredictionModelToolkit,
) -> dict[str, Any]:
    """Compile the final incident prediction report."""
    logger.info("ipm.node.report")
    state = _to_dict(state)

    total_indicators = state.get("total_indicators", 0)
    prediction_count = state.get("predictions_generated", 0)
    warning_count = len(state.get("warnings", []))
    conf_count = len(state.get("confidence_assessments", []))

    lines = [
        "# Incident Prediction Report",
        "",
        f"**Indicators collected:** {total_indicators}",
        f"**Predictions generated:** {prediction_count}",
        f"**Confidence assessed:** {conf_count}",
        f"**Warnings issued:** {warning_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "total_indicators": total_indicators,
                "predictions": prediction_count,
                "confidence_assessments": conf_count,
                "warnings": warning_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Incident prediction report:\n{ctx}",
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="ipm",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="ipm",
            node="report",
        )

    return {
        "stage": IPMStage.REPORT.value,
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
