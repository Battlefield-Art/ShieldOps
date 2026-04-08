"""Node implementations for the Data Catalog Protector
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.data_catalog_protector.models import (
    DataCatalogProtectorState,
    DCPStage,
    ReasoningStep,
)
from shieldops.agents.data_catalog_protector.prompts import (
    SYSTEM_CLASSIFICATION,
    SYSTEM_ENFORCEMENT,
    SYSTEM_REPORT,
    SYSTEM_VIOLATION,
    CatalogClassificationOutput,
    CatalogReportOutput,
    EnforcementRecommendationOutput,
    ViolationDetectionOutput,
)
from shieldops.agents.data_catalog_protector.tools import (
    DataCatalogProtectorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: DataCatalogProtectorToolkit | None = None


def _get_toolkit() -> DataCatalogProtectorToolkit:
    if _toolkit is None:
        return DataCatalogProtectorToolkit()
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
# Node: scan_catalogs
# ------------------------------------------------------------------


async def scan_catalogs(
    state: DataCatalogProtectorState,
) -> dict[str, Any]:
    """Scan configured data catalogs for tables and
    column metadata."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.scan_catalogs(
        catalog_names=state.catalog_names,
        scope=state.scan_scope,
    )

    total = sum(r.get("tables_scanned", 0) for r in results)

    step = _step(
        state.reasoning_chain,
        "scan_catalogs",
        f"Scanning {len(state.catalog_names)} catalogs",
        f"Scanned {total} tables",
        start,
        "catalog_scanner",
    )

    return {
        "scan_results": results,
        "total_tables_scanned": total,
        "stage": DCPStage.SCAN_CATALOGS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "scan_catalogs",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: classify_sensitivity
# ------------------------------------------------------------------


async def classify_sensitivity(
    state: DataCatalogProtectorState,
) -> dict[str, Any]:
    """Classify scanned tables by data sensitivity
    level."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    classifications = await toolkit.classify_sensitivity(
        scan_results=state.scan_results,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "tables_scanned": state.total_tables_scanned,
                "scan_sample": state.scan_results[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_CLASSIFICATION,
            user_prompt=f"Classify sensitivity:\n{ctx}",
            schema=CatalogClassificationOutput,
        )
        if llm_out.classifications:  # type: ignore[union-attr]
            classifications = [
                *classifications,
                *llm_out.classifications,  # type: ignore[union-attr]
            ]
        pii_count = len(llm_out.pii_columns_found)  # type: ignore[union-attr]
        logger.info(
            "llm_enhanced",
            node="classify_sensitivity",
            pii_found=pii_count,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="classify_sensitivity",
        )

    pii_total = sum(c.get("pii_count", 0) for c in classifications)

    step = _step(
        state.reasoning_chain,
        "classify_sensitivity",
        f"Classifying {state.total_tables_scanned} tables",
        f"Classified with {pii_total} PII columns",
        start,
        "classifier",
    )

    return {
        "classifications": classifications,
        "pii_detected": pii_total,
        "stage": DCPStage.CLASSIFY_SENSITIVITY,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "classify_sensitivity",
    }


# ------------------------------------------------------------------
# Node: map_access
# ------------------------------------------------------------------


async def map_access(
    state: DataCatalogProtectorState,
) -> dict[str, Any]:
    """Map access patterns across classified catalog
    entries."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    patterns = await toolkit.map_access_patterns(
        catalog_entries=state.classifications,
        scope=state.scan_scope,
    )

    step = _step(
        state.reasoning_chain,
        "map_access",
        f"Mapping access for {len(state.classifications)} entries",
        f"Found {len(patterns)} access patterns",
        start,
        "access_mapper",
    )

    return {
        "access_patterns": patterns,
        "stage": DCPStage.MAP_ACCESS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "map_access",
    }


# ------------------------------------------------------------------
# Node: detect_violations
# ------------------------------------------------------------------


async def detect_violations(
    state: DataCatalogProtectorState,
) -> dict[str, Any]:
    """Detect access policy violations from mapped
    patterns."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    violations = await toolkit.detect_violations(
        access_patterns=state.access_patterns,
        classifications=state.classifications,
        policy_rules=state.policy_rules,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "pattern_count": len(state.access_patterns),
                "patterns_sample": state.access_patterns[:5],
                "classifications_sample": (state.classifications[:5]),
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_VIOLATION,
            user_prompt=f"Detect violations:\n{ctx}",
            schema=ViolationDetectionOutput,
        )
        if llm_out.violations:  # type: ignore[union-attr]
            rand_id = random.randint(1000, 9999)  # noqa: S311
            for v in llm_out.violations:  # type: ignore[union-attr]
                violations.append(
                    {
                        "violation_id": f"llm-{rand_id}",
                        "type": v.get("type", "policy_breach"),
                        "severity": v.get("severity", "medium"),
                        "description": v.get("description", ""),
                    }
                )
        logger.info(
            "llm_enhanced",
            node="detect_violations",
            risk_score=llm_out.risk_score,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_violations",
        )

    step = _step(
        state.reasoning_chain,
        "detect_violations",
        f"Checking {len(state.access_patterns)} patterns",
        f"Detected {len(violations)} violations",
        start,
        "violation_detector",
    )

    return {
        "violations": violations,
        "violations_found": len(violations),
        "stage": DCPStage.DETECT_VIOLATIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_violations",
    }


# ------------------------------------------------------------------
# Node: enforce_policies
# ------------------------------------------------------------------


async def enforce_policies(
    state: DataCatalogProtectorState,
) -> dict[str, Any]:
    """Enforce remediation for detected violations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    enforcements = await toolkit.enforce_policies(
        violations=state.violations,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "violations": state.violations[:10],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ENFORCEMENT,
            user_prompt=f"Recommend enforcement:\n{ctx}",
            schema=EnforcementRecommendationOutput,
        )
        if llm_out.actions:  # type: ignore[union-attr]
            enforcements = [
                *enforcements,
                *llm_out.actions,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="enforce_policies",
            actions=len(llm_out.actions),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="enforce_policies",
        )

    step = _step(
        state.reasoning_chain,
        "enforce_policies",
        f"Enforcing {state.violations_found} violations",
        f"Applied {len(enforcements)} enforcements",
        start,
        "enforcer",
    )

    return {
        "enforcements": enforcements,
        "enforcements_applied": len(enforcements),
        "stage": DCPStage.ENFORCE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "enforce_policies",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: DataCatalogProtectorState,
) -> dict[str, Any]:
    """Generate the final catalog protection report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report = await toolkit.generate_report(
        scan_results=state.scan_results,
        violations=state.violations,
        enforcements=state.enforcements,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "tables_scanned": state.total_tables_scanned,
                "pii_detected": state.pii_detected,
                "violations_found": state.violations_found,
                "enforcements_applied": state.enforcements_applied,
                "violations_sample": state.violations[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate report:\n{ctx}",
            schema=CatalogReportOutput,
        )
        if isinstance(llm_out, CatalogReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "recommendations": llm_out.recommendations,
                    "risk_rating": llm_out.risk_rating,
                    "compliance_gaps": llm_out.compliance_gaps,
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

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    await toolkit.record_metric(
        metric_name="catalog_protection_run",
        value=float(state.violations_found),
        labels={"tables": str(state.total_tables_scanned)},
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.violations_found} violations",
        f"Report generated, {state.enforcements_applied} enforced",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": DCPStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
