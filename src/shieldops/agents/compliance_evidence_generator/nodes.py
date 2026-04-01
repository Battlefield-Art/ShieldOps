"""Compliance Evidence Generator — Node function implementations."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.compliance_evidence_generator.models import (
    CEGStage,
    ComplianceEvidenceGeneratorState,
    ReasoningStep,
)
from shieldops.agents.compliance_evidence_generator.prompts import (
    SYSTEM_COLLECT_EVIDENCE,
    SYSTEM_IDENTIFY_CONTROLS,
    SYSTEM_IDENTIFY_GAPS,
    SYSTEM_PACKAGE_EVIDENCE,
    SYSTEM_VALIDATE_EVIDENCE,
    ControlIdentificationOutput,
    EvidenceCollectionOutput,
    EvidenceValidationOutput,
    GapIdentificationOutput,
    PackagingOutput,
)
from shieldops.agents.compliance_evidence_generator.tools import (
    ComplianceEvidenceGeneratorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ComplianceEvidenceGeneratorToolkit | None = None


def set_toolkit(
    toolkit: ComplianceEvidenceGeneratorToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> ComplianceEvidenceGeneratorToolkit:
    if _toolkit is None:
        return ComplianceEvidenceGeneratorToolkit()
    return _toolkit


def _step(
    state: ComplianceEvidenceGeneratorState,
    action: str,
    input_summary: str,
    output_summary: str,
    duration_ms: int,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Create a reasoning step."""
    return ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=duration_ms,
        tool_used=tool_used,
    )


async def identify_controls(
    state: ComplianceEvidenceGeneratorState,
) -> dict[str, Any]:
    """Identify applicable controls for requested compliance frameworks."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    frameworks = state.config.get("frameworks", ["soc2"])
    raw = await toolkit.identify_controls(frameworks)
    critical = sum(1 for c in raw if c.get("criticality") == "critical")

    try:
        ctx = _json.dumps(
            {"frameworks": frameworks, "control_count": len(raw), "critical": critical},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_IDENTIFY_CONTROLS,
            user_prompt=f"Control identification context:\n{ctx}",
            schema=ControlIdentificationOutput,
        )
        if hasattr(llm_result, "total_controls"):
            logger.info("llm_enhanced", node="identify_controls")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="identify_controls")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "identify_controls",
        f"frameworks={frameworks}",
        f"found {len(raw)} controls, {critical} critical",
        elapsed,
        "config_store",
    )
    await toolkit.record_metric("controls_identified", float(len(raw)))

    return {
        "controls": raw,
        "stage": CEGStage.COLLECT_EVIDENCE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "identify_controls",
        "session_start": start,
    }


async def collect_evidence(
    state: ComplianceEvidenceGeneratorState,
) -> dict[str, Any]:
    """Collect evidence artifacts for identified controls."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    artifacts = await toolkit.collect_evidence(state.controls)

    try:
        ctx = _json.dumps(
            {"control_count": len(state.controls), "artifact_count": len(artifacts)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_COLLECT_EVIDENCE,
            user_prompt=f"Evidence collection context:\n{ctx}",
            schema=EvidenceCollectionOutput,
        )
        if hasattr(llm_result, "artifacts_collected"):
            logger.info("llm_enhanced", node="collect_evidence")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="collect_evidence")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "collect_evidence",
        f"collecting for {len(state.controls)} controls",
        f"collected {len(artifacts)} artifacts",
        elapsed,
        "telemetry_client",
    )
    await toolkit.record_metric("artifacts_collected", float(len(artifacts)))

    return {
        "evidence": artifacts,
        "stage": CEGStage.VALIDATE_EVIDENCE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_evidence",
    }


async def validate_evidence(
    state: ComplianceEvidenceGeneratorState,
) -> dict[str, Any]:
    """Validate collected evidence artifacts."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.validate_evidence(state.evidence, state.controls)
    valid_count = sum(1 for r in results if r.get("is_valid", False))
    invalid_count = len(results) - valid_count

    try:
        ctx = _json.dumps(
            {
                "artifact_count": len(state.evidence),
                "valid": valid_count,
                "invalid": invalid_count,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_VALIDATE_EVIDENCE,
            user_prompt=f"Evidence validation context:\n{ctx}",
            schema=EvidenceValidationOutput,
        )
        if hasattr(llm_result, "valid_artifacts"):
            logger.info("llm_enhanced", node="validate_evidence")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="validate_evidence")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "validate_evidence",
        f"validating {len(state.evidence)} artifacts",
        f"{valid_count} valid, {invalid_count} invalid",
        elapsed,
        "evidence_store",
    )
    await toolkit.record_metric("evidence_validated", float(valid_count))

    return {
        "validation_results": results,
        "stage": CEGStage.IDENTIFY_GAPS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "validate_evidence",
    }


async def identify_gaps(
    state: ComplianceEvidenceGeneratorState,
) -> dict[str, Any]:
    """Identify compliance gaps from validation results."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    gaps = await toolkit.identify_gaps(state.controls, state.validation_results)
    critical_gaps = sum(1 for g in gaps if g.get("severity") == "critical")

    try:
        ctx = _json.dumps(
            {
                "control_count": len(state.controls),
                "total_gaps": len(gaps),
                "critical_gaps": critical_gaps,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_IDENTIFY_GAPS,
            user_prompt=f"Gap identification context:\n{ctx}",
            schema=GapIdentificationOutput,
        )
        if hasattr(llm_result, "total_gaps"):
            logger.info("llm_enhanced", node="identify_gaps")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="identify_gaps")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "identify_gaps",
        f"analyzing {len(state.controls)} controls",
        f"{len(gaps)} gaps found, {critical_gaps} critical",
        elapsed,
        "gap_analyzer",
    )
    await toolkit.record_metric("gaps_identified", float(len(gaps)))

    return {
        "gaps": gaps,
        "stage": CEGStage.PACKAGE_EVIDENCE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "identify_gaps",
    }


async def package_evidence(
    state: ComplianceEvidenceGeneratorState,
) -> dict[str, Any]:
    """Package validated evidence into audit-ready packages."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    frameworks = state.config.get("frameworks", ["soc2"])
    packages = await toolkit.package_evidence(
        frameworks,
        state.controls,
        state.evidence,
        state.validation_results,
        state.gaps,
    )

    avg_completeness = (
        round(sum(p.get("completeness_score", 0) for p in packages) / len(packages), 4)
        if packages
        else 0.0
    )

    try:
        ctx = _json.dumps(
            {
                "framework_count": len(frameworks),
                "packages": len(packages),
                "avg_completeness": avg_completeness,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_PACKAGE_EVIDENCE,
            user_prompt=f"Evidence packaging context:\n{ctx}",
            schema=PackagingOutput,
        )
        if hasattr(llm_result, "packages_created"):
            logger.info("llm_enhanced", node="package_evidence")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="package_evidence")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "package_evidence",
        f"packaging {len(frameworks)} frameworks",
        f"{len(packages)} packages, avg completeness={avg_completeness}",
        elapsed,
        "evidence_packager",
    )
    await toolkit.record_metric("packages_created", float(len(packages)))

    return {
        "packages": packages,
        "stage": CEGStage.GENERATE_REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "package_evidence",
    }


async def generate_report(
    state: ComplianceEvidenceGeneratorState,
) -> dict[str, Any]:
    """Generate final compliance evidence report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    frameworks = state.config.get("frameworks", ["soc2"])
    valid_count = sum(1 for vr in state.validation_results if vr.get("is_valid", False))
    total_required = sum(len(c.get("required_evidence_types", [])) for c in state.controls)
    overall_completeness = round(valid_count / total_required, 4) if total_required > 0 else 0.0

    recommendations: list[str] = []
    critical_gaps = [g for g in state.gaps if g.get("severity") == "critical"]
    if critical_gaps:
        recommendations.append(
            f"Remediate {len(critical_gaps)} critical gaps before audit submission"
        )
    low_packages = [p for p in state.packages if p.get("completeness_score", 0) < 0.8]
    if low_packages:
        fws = [p.get("framework", "") for p in low_packages]
        recommendations.append(f"Improve evidence coverage for: {', '.join(fws)}")
    if not recommendations:
        recommendations.append("All frameworks meet minimum evidence thresholds")

    report = {
        "report_id": f"rpt-{state.request_id}",
        "frameworks": frameworks,
        "total_controls": len(state.controls),
        "evidence_collected": len(state.evidence),
        "evidence_valid": valid_count,
        "gaps_found": len(state.gaps),
        "overall_completeness": overall_completeness,
        "packages": [p for p in state.packages],
        "recommendations": recommendations,
        "duration_ms": duration_ms,
        "generated_at": datetime.now(UTC).isoformat(),
    }

    await toolkit.record_metric("report_completeness", overall_completeness)
    await toolkit.record_metric("scan_duration_ms", float(duration_ms))

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "generate_report",
        f"finalizing {state.request_id}",
        f"report complete, completeness={overall_completeness}, duration={duration_ms}ms",
        elapsed,
        None,
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
