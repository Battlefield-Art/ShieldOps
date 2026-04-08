"""Node implementations for the Compliance Evidence Collector."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.compliance_evidence_collector.models import (
    ComplianceEvidenceCollectorState,
    EvidenceStage,
    ReasoningStep,
)
from shieldops.agents.compliance_evidence_collector.prompts import (
    SYSTEM_COLLECT,
    SYSTEM_IDENTIFY,
    SYSTEM_MAP,
    SYSTEM_REPORT,
    SYSTEM_VALIDATE,
    ControlIdentificationOutput,
    EvidenceCollectionOutput,
    FrameworkMappingOutput,
    ReportOutput,
    ValidationOutput,
)
from shieldops.agents.compliance_evidence_collector.tools import (
    ComplianceEvidenceCollectorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ComplianceEvidenceCollectorToolkit | None = None


def _get_toolkit() -> ComplianceEvidenceCollectorToolkit:
    if _toolkit is None:
        return ComplianceEvidenceCollectorToolkit()
    return _toolkit


def _step(
    state: ComplianceEvidenceCollectorState,
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
    state: ComplianceEvidenceCollectorState,
) -> dict[str, Any]:
    """Identify control requirements for target frameworks."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.identify_controls(state.scan_config)
    total = len(raw)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "frameworks": state.scan_config.get("frameworks", []),
                "control_count": total,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_IDENTIFY,
            user_prompt=(f"Control identification context:\n{ctx}"),
            schema=ControlIdentificationOutput,
        )
        if hasattr(llm_result, "total_controls") and llm_result.total_controls > total:
            total = llm_result.total_controls
        logger.info(
            "llm_enhanced",
            node="identify_controls",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="identify_controls",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "identify_controls",
        f"frameworks={state.scan_config.get('frameworks', [])}",
        f"identified {total} controls",
        elapsed,
        "policy_store",
    )
    await toolkit.record_metric("controls_identified", float(total))

    return {
        "control_requirements": raw,
        "total_controls": total,
        "stage": EvidenceStage.COLLECT_EVIDENCE,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "identify_controls",
        "session_start": start,
    }


async def collect_evidence(
    state: ComplianceEvidenceCollectorState,
) -> dict[str, Any]:
    """Collect evidence items for identified controls."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    items = await toolkit.collect_evidence(
        state.control_requirements,
    )
    collected = sum(1 for i in items if i.get("status") == "collected")

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "control_count": len(state.control_requirements),
                "items_collected": collected,
                "items_missing": len(items) - collected,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_COLLECT,
            user_prompt=(f"Evidence collection context:\n{ctx}"),
            schema=EvidenceCollectionOutput,
        )
        if hasattr(llm_result, "collected_count") and llm_result.collected_count > collected:
            collected = llm_result.collected_count
        logger.info(
            "llm_enhanced",
            node="collect_evidence",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="collect_evidence",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "collect_evidence",
        f"collecting for {len(state.control_requirements)} controls",
        f"{collected}/{len(items)} items collected",
        elapsed,
        "log_collector",
    )

    return {
        "evidence_items": items,
        "collected_count": collected,
        "stage": EvidenceStage.VALIDATE,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "collect_evidence",
    }


async def validate_evidence(
    state: ComplianceEvidenceCollectorState,
) -> dict[str, Any]:
    """Validate collected evidence items."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.validate_evidence(
        state.evidence_items,
    )
    valid = sum(1 for r in results if r.get("is_valid"))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "item_count": len(state.evidence_items),
                "valid_count": valid,
                "results": results[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_VALIDATE,
            user_prompt=(f"Evidence validation context:\n{ctx}"),
            schema=ValidationOutput,
        )
        if hasattr(llm_result, "valid_count") and llm_result.valid_count > valid:
            valid = llm_result.valid_count
        logger.info(
            "llm_enhanced",
            node="validate_evidence",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="validate_evidence",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "validate_evidence",
        f"validating {len(state.evidence_items)} items",
        f"{valid} valid items",
        elapsed,
        "config_scanner",
    )
    await toolkit.record_metric("valid_evidence", float(valid))

    return {
        "validation_results": results,
        "valid_count": valid,
        "stage": EvidenceStage.MAP_FRAMEWORKS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "validate_evidence",
    }


async def map_frameworks(
    state: ComplianceEvidenceCollectorState,
) -> dict[str, Any]:
    """Map controls across compliance frameworks."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    mappings = await toolkit.map_frameworks(
        state.control_requirements,
        state.validation_results,
    )
    avg_coverage = (
        sum(m.get("coverage_pct", 0) for m in mappings) / len(mappings) if mappings else 0.0
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "control_count": len(state.control_requirements),
                "mapping_count": len(mappings),
                "avg_coverage": round(avg_coverage, 1),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_MAP,
            user_prompt=(f"Framework mapping context:\n{ctx}"),
            schema=FrameworkMappingOutput,
        )
        if hasattr(llm_result, "coverage_pct") and llm_result.coverage_pct > avg_coverage:
            avg_coverage = round(
                (avg_coverage + llm_result.coverage_pct) / 2,
                1,
            )
        logger.info(
            "llm_enhanced",
            node="map_frameworks",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="map_frameworks",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "map_frameworks",
        f"mapping {len(state.control_requirements)} controls",
        f"coverage={round(avg_coverage, 1)}%",
        elapsed,
        "policy_store",
    )

    return {
        "framework_mappings": mappings,
        "coverage_pct": round(avg_coverage, 1),
        "stage": EvidenceStage.GENERATE_REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "map_frameworks",
    }


async def generate_compliance_report(
    state: ComplianceEvidenceCollectorState,
) -> dict[str, Any]:
    """Generate compliance report sections."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    sections = await toolkit.generate_report(
        state.framework_mappings,
        state.evidence_items,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "mapping_count": len(state.framework_mappings),
                "section_count": len(sections),
                "coverage_pct": state.coverage_pct,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Report generation context:\n{ctx}"),
            schema=ReportOutput,
        )
        if hasattr(llm_result, "sections"):
            logger.info(
                "llm_enhanced",
                node="generate_compliance_report",
                llm_sections=len(llm_result.sections),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_compliance_report",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "generate_compliance_report",
        f"generating report from {len(state.framework_mappings)} mappings",
        f"created {len(sections)} report sections",
        elapsed,
        "report_engine",
    )

    return {
        "report_sections": sections,
        "stage": EvidenceStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "generate_compliance_report",
    }


async def generate_report(
    state: ComplianceEvidenceCollectorState,
) -> dict[str, Any]:
    """Generate final evidence collection report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report = {
        "request_id": state.request_id,
        "total_controls": state.total_controls,
        "evidence_collected": state.collected_count,
        "evidence_valid": state.valid_count,
        "coverage_pct": state.coverage_pct,
        "report_sections": len(state.report_sections),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric("scan_duration_ms", float(duration_ms))
    await toolkit.record_metric(
        "coverage_pct",
        state.coverage_pct,
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "generate_report",
        f"finalizing scan {state.request_id}",
        f"report complete in {duration_ms}ms",
        elapsed,
        None,
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "complete",
    }
