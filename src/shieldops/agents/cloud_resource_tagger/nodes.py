"""Node implementations for the Cloud Resource Tagger
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.cloud_resource_tagger.models import (
    CloudResourceTaggerState,
    TagStage,
)
from shieldops.agents.cloud_resource_tagger.prompts import (
    SYSTEM_COMPLIANCE,
    SYSTEM_REPORT,
    SYSTEM_SCAN,
    SYSTEM_TAG_GENERATION,
    ComplianceValidationOutput,
    ResourceScanOutput,
    TagGenerationOutput,
    TagReportOutput,
)
from shieldops.agents.cloud_resource_tagger.tools import (
    CloudResourceTaggerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: CloudResourceTaggerToolkit | None = None


def _get_toolkit() -> CloudResourceTaggerToolkit:
    if _toolkit is None:
        return CloudResourceTaggerToolkit()
    return _toolkit


# ------------------------------------------------------------------
# Node: scan_resources
# ------------------------------------------------------------------


async def scan_resources(
    state: CloudResourceTaggerState,
) -> dict[str, Any]:
    """Scan cloud resources for tagging status."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    resources = await toolkit.scan_resources(
        tenant_id=state.tenant_id,
    )

    try:
        ctx = _json.dumps(
            {"tenant_id": state.tenant_id, "sample": resources[:5]},
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_SCAN,
            user_prompt=f"Scan resources:\n{ctx}",
            schema=ResourceScanOutput,
        )
        if llm_out.resources:  # type: ignore[union-attr]
            resources = [*resources, *llm_out.resources]  # type: ignore[union-attr]
        logger.info(
            "llm_enhanced",
            node="scan_resources",
            count=len(llm_out.resources),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="scan_resources")

    untagged = sum(1 for r in resources if r.get("tag_count", 0) == 0)

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "resources": resources,
        "total_resources": len(resources),
        "untagged_count": untagged,
        "stage": TagStage.SCAN_RESOURCES,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Scanned {len(resources)} resources, {untagged} untagged ({elapsed}ms)",
        ],
        "current_step": "scan_resources",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: analyze_metadata
# ------------------------------------------------------------------


async def analyze_metadata(
    state: CloudResourceTaggerState,
) -> dict[str, Any]:
    """Analyze resource metadata for tag inference."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    analyses = await toolkit.analyze_metadata(
        resources=state.resources,
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "metadata_analyses": analyses,
        "stage": TagStage.ANALYZE_METADATA,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Analyzed metadata for {len(analyses)} resources ({elapsed}ms)",
        ],
        "current_step": "analyze_metadata",
    }


# ------------------------------------------------------------------
# Node: generate_tags
# ------------------------------------------------------------------


async def generate_tags(
    state: CloudResourceTaggerState,
) -> dict[str, Any]:
    """Generate tag recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    tags = await toolkit.generate_tags(
        resources=state.resources,
        metadata=state.metadata_analyses,
    )

    try:
        ctx = _json.dumps(
            {
                "resources": state.resources[:5],
                "metadata": state.metadata_analyses[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_TAG_GENERATION,
            user_prompt=f"Generate tags:\n{ctx}",
            schema=TagGenerationOutput,
        )
        if llm_out.recommendations:  # type: ignore[union-attr]
            tags = [*tags, *llm_out.recommendations]  # type: ignore[union-attr]
        logger.info(
            "llm_enhanced",
            node="generate_tags",
            count=len(llm_out.recommendations),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="generate_tags")

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "tag_recommendations": tags,
        "stage": TagStage.GENERATE_TAGS,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Generated {len(tags)} tag recommendations ({elapsed}ms)",
        ],
        "current_step": "generate_tags",
    }


# ------------------------------------------------------------------
# Node: validate_compliance
# ------------------------------------------------------------------


async def validate_compliance(
    state: CloudResourceTaggerState,
) -> dict[str, Any]:
    """Validate tag compliance."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.validate_compliance(
        resources=state.resources,
        tags=state.tag_recommendations,
    )

    try:
        ctx = _json.dumps(
            {
                "total": state.total_resources,
                "tags": state.tag_recommendations[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_COMPLIANCE,
            user_prompt=f"Validate compliance:\n{ctx}",
            schema=ComplianceValidationOutput,
        )
        if isinstance(llm_out, ComplianceValidationOutput):
            compliance_pct = llm_out.compliance_pct
        else:
            total = state.total_resources
            compliance_pct = 0.0 if total == 0 else round((len(results) / total) * 100, 1)
        logger.info("llm_enhanced", node="validate_compliance")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="validate_compliance",
        )
        total = state.total_resources
        compliance_pct = 0.0 if total == 0 else round((len(results) / total) * 100, 1)

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "compliance_results": results,
        "compliance_pct": compliance_pct,
        "stage": TagStage.VALIDATE_COMPLIANCE,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Compliance: {compliance_pct}% ({elapsed}ms)",
        ],
        "current_step": "validate_compliance",
    }


# ------------------------------------------------------------------
# Node: apply_tags
# ------------------------------------------------------------------


async def apply_tags(
    state: CloudResourceTaggerState,
) -> dict[str, Any]:
    """Apply approved tags to resources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    applied = await toolkit.apply_tags(
        recommendations=state.tag_recommendations,
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return {
        "applied_tags": applied,
        "stage": TagStage.APPLY_TAGS,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Applied {len(applied)} tags ({elapsed}ms)",
        ],
        "current_step": "apply_tags",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: CloudResourceTaggerState,
) -> dict[str, Any]:
    """Generate tagging report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {
        "total_resources": state.total_resources,
        "untagged_count": state.untagged_count,
        "compliance_pct": state.compliance_pct,
        "tags_applied": len(state.applied_tags),
    }

    try:
        ctx = _json.dumps(report, default=str)
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate tagging report:\n{ctx}",
            schema=TagReportOutput,
        )
        if isinstance(llm_out, TagReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "recommendations": llm_out.recommendations,
                }
            )
        logger.info("llm_enhanced", node="generate_report")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="generate_report")

    await toolkit.record_metric("compliance_pct", state.compliance_pct)

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    return {
        "stats": report,
        "stage": TagStage.REPORT,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"Report generated ({elapsed}ms)",
        ],
        "current_step": "complete",
    }
