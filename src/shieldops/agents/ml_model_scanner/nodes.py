"""Node implementations for the ML Model Scanner
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.ml_model_scanner.models import (
    MLModelScannerState,
    MMSStage,
    ReasoningStep,
)
from shieldops.agents.ml_model_scanner.prompts import (
    SYSTEM_BACKDOOR,
    SYSTEM_REPORT,
    SYSTEM_SCAN,
    ArtifactScanOutput,
    BackdoorDetectionOutput,
    ModelScanReportOutput,
)
from shieldops.agents.ml_model_scanner.tools import (
    MLModelScannerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: MLModelScannerToolkit | None = None


def set_toolkit(
    toolkit: MLModelScannerToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> MLModelScannerToolkit:
    if _toolkit is None:
        return MLModelScannerToolkit()
    return _toolkit


def _step(
    chain: list[ReasoningStep],
    action: str,
    input_summary: str,
    output_summary: str,
    start: datetime,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Build a reasoning step with duration."""
    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return ReasoningStep(
        step_number=len(chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=elapsed,
        tool_used=tool_used,
    )


# ------------------------------------------------------------------
# Node: discover_models
# ------------------------------------------------------------------


async def discover_models(
    state: MLModelScannerState,
) -> dict[str, Any]:
    """Discover ML model artifacts across configured
    registries and artifact stores."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    artifacts = await toolkit.discover_models(
        registries=state.registries,
        scope=state.scope,
    )

    step = _step(
        state.reasoning_chain,
        "discover_models",
        f"Scanning {len(state.registries)} registries",
        f"Discovered {len(artifacts)} model artifacts",
        start,
        "registry_client",
    )

    return {
        "artifacts": artifacts,
        "total_models": len(artifacts),
        "stage": MMSStage.DISCOVER_MODELS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "discover_models",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: scan_artifacts
# ------------------------------------------------------------------


async def scan_artifacts(
    state: MLModelScannerState,
) -> dict[str, Any]:
    """Scan discovered model artifacts for security
    vulnerabilities and unsafe operations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    scan_results = await toolkit.scan_artifacts(
        artifacts=state.artifacts,
        formats_filter=state.formats_filter,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "artifact_count": len(state.artifacts),
                "artifacts_sample": state.artifacts[:5],
                "formats": state.formats_filter,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_SCAN,
            user_prompt=f"Scan model artifacts:\n{ctx}",
            schema=ArtifactScanOutput,
        )
        if llm_out.vulnerabilities:  # type: ignore[union-attr]
            scan_results.append(
                {
                    "scan_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "vulnerabilities": (llm_out.vulnerabilities),  # type: ignore[union-attr]
                    "unsafe_operations": (llm_out.unsafe_operations),  # type: ignore[union-attr]
                    "pickle_risk": llm_out.pickle_risk,  # type: ignore[union-attr]
                    "risk_level": llm_out.risk_level,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="scan_artifacts",
            vulns=len(llm_out.vulnerabilities),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="scan_artifacts",
        )

    step = _step(
        state.reasoning_chain,
        "scan_artifacts",
        f"Scanning {len(state.artifacts)} artifacts",
        f"Produced {len(scan_results)} scan results",
        start,
        "artifact_scanner",
    )

    return {
        "scan_results": scan_results,
        "stage": MMSStage.SCAN_ARTIFACTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "scan_artifacts",
    }


# ------------------------------------------------------------------
# Node: check_provenance
# ------------------------------------------------------------------


async def check_provenance(
    state: MLModelScannerState,
) -> dict[str, Any]:
    """Verify provenance chain for discovered model
    artifacts."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    provenance_records = await toolkit.check_provenance(
        artifacts=state.artifacts,
    )

    step = _step(
        state.reasoning_chain,
        "check_provenance",
        f"Checking provenance for {len(state.artifacts)} artifacts",
        f"Verified {len(provenance_records)} provenance records",
        start,
        "provenance_service",
    )

    return {
        "provenance_records": provenance_records,
        "stage": MMSStage.CHECK_PROVENANCE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "check_provenance",
    }


# ------------------------------------------------------------------
# Node: detect_backdoors
# ------------------------------------------------------------------


async def detect_backdoors(
    state: MLModelScannerState,
) -> dict[str, Any]:
    """Detect potential backdoors and poisoning in
    model weights and architecture."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    backdoor_indicators = await toolkit.detect_backdoors(
        artifacts=state.artifacts,
        scan_results=state.scan_results,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "artifact_count": len(state.artifacts),
                "scan_results_sample": state.scan_results[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_BACKDOOR,
            user_prompt=(f"Detect backdoors:\n{ctx}"),
            schema=BackdoorDetectionOutput,
        )
        if llm_out.indicators:  # type: ignore[union-attr]
            backdoor_indicators.append(
                {
                    "indicator_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "backdoor_detected": (llm_out.backdoor_detected),  # type: ignore[union-attr]
                    "indicators": llm_out.indicators,  # type: ignore[union-attr]
                    "confidence": llm_out.confidence,  # type: ignore[union-attr]
                    "affected_layers": (llm_out.affected_layers),  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="detect_backdoors",
            detected=llm_out.backdoor_detected,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_backdoors",
        )

    step = _step(
        state.reasoning_chain,
        "detect_backdoors",
        f"Analyzing {len(state.artifacts)} artifacts for backdoors",
        f"Found {len(backdoor_indicators)} indicators",
        start,
        "backdoor_detector",
    )

    return {
        "backdoor_indicators": backdoor_indicators,
        "stage": MMSStage.DETECT_BACKDOORS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_backdoors",
    }


# ------------------------------------------------------------------
# Node: assess_risk
# ------------------------------------------------------------------


async def assess_risk(
    state: MLModelScannerState,
) -> dict[str, Any]:
    """Compute aggregate risk assessment for each model
    artifact."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    risk_assessments = await toolkit.assess_risk(
        artifacts=state.artifacts,
        scan_results=state.scan_results,
        provenance=state.provenance_records,
        backdoors=state.backdoor_indicators,
    )

    # Compute summary metrics
    _vulnerable = sum(1 for r in risk_assessments if r.get("overall_risk") in ("critical", "high"))
    _critical = sum(1 for r in risk_assessments if r.get("overall_risk") == "critical")
    _scores = [r.get("risk_score", 0.0) for r in risk_assessments]
    _avg_risk = sum(_scores) / max(len(_scores), 1)

    step = _step(
        state.reasoning_chain,
        "assess_risk",
        (
            f"Assessing risk for {len(state.artifacts)} "
            f"artifacts with {len(state.scan_results)} scan results"
        ),
        f"Assessed {len(risk_assessments)} models, {_vulnerable} vulnerable",
        start,
        "risk_engine",
    )

    return {
        "risk_assessments": risk_assessments,
        "vulnerable_models": _vulnerable,
        "critical_count": _critical,
        "overall_risk_score": _avg_risk,
        "stage": MMSStage.ASSESS_RISK,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_risk",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: MLModelScannerState,
) -> dict[str, Any]:
    """Generate the final ML model scan report with
    executive summary and recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {
        "scan_name": state.scan_name,
        "total_models": state.total_models,
        "vulnerable_models": state.vulnerable_models,
        "critical_count": state.critical_count,
        "overall_risk_score": state.overall_risk_score,
    }

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "scan_name": state.scan_name,
                "total_models": state.total_models,
                "vulnerable_models": state.vulnerable_models,
                "critical_count": state.critical_count,
                "scan_results_sample": state.scan_results[:5],
                "risk_assessments_sample": (state.risk_assessments[:5]),
                "backdoor_indicators": (state.backdoor_indicators[:5]),
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate scan report:\n{ctx}"),
            schema=ModelScanReportOutput,
        )
        if isinstance(llm_out, ModelScanReportOutput):
            report.update(
                {
                    "executive_summary": (llm_out.executive_summary),
                    "critical_findings": (llm_out.critical_findings),
                    "recommendations": llm_out.recommendations,
                    "overall_risk": llm_out.overall_risk,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                recommendations=len(llm_out.recommendations),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    # Record metrics
    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    await toolkit.record_metric(
        scan_id=state.request_id,
        outcome={
            "total_models": state.total_models,
            "vulnerable_models": state.vulnerable_models,
            "critical_count": state.critical_count,
            "overall_risk_score": state.overall_risk_score,
            "duration_ms": duration_ms,
        },
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        (f"Reporting on {state.total_models} models"),
        (f"Report generated, risk_score={state.overall_risk_score:.2f}"),
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": MMSStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
