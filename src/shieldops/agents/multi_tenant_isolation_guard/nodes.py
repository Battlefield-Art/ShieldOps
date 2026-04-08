"""Node implementations for the Multi-Tenant Isolation Guard."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.multi_tenant_isolation_guard.models import (
    MTIGStage,
    MultiTenantIsolationGuardState,
    ReasoningStep,
)
from shieldops.agents.multi_tenant_isolation_guard.prompts import (
    SYSTEM_ASSESS,
    SYSTEM_ENFORCE,
    SYSTEM_LEAKAGE,
    SYSTEM_MAP,
    SYSTEM_SCAN,
    AssessmentOutput,
    BoundaryScanOutput,
    EnforcementOutput,
    LeakageOutput,
    TenantMapOutput,
)
from shieldops.agents.multi_tenant_isolation_guard.tools import (
    MultiTenantIsolationGuardToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: MultiTenantIsolationGuardToolkit | None = None


def _get_toolkit() -> MultiTenantIsolationGuardToolkit:
    if _toolkit is None:
        return MultiTenantIsolationGuardToolkit()
    return _toolkit


def _step(
    state: MultiTenantIsolationGuardState,
    action: str,
    input_summary: str,
    output_summary: str,
    duration_ms: int,
    tool_used: str | None = None,
) -> ReasoningStep:
    return ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=duration_ms,
        tool_used=tool_used,
    )


async def map_tenants(
    state: MultiTenantIsolationGuardState,
) -> dict[str, Any]:
    """Map tenant resources and boundaries."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    mappings = await toolkit.map_tenants(state.config)

    try:
        ctx = _json.dumps(
            {"count": len(mappings)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_MAP,
            user_prompt=f"Tenant mapping context:\n{ctx}",
            schema=TenantMapOutput,
        )
        if hasattr(llm_result, "tenants_mapped"):
            logger.info("llm_enhanced", node="map_tenants")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="map_tenants",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "map_tenants",
        f"config={state.config}",
        f"mapped {len(mappings)} tenants",
        elapsed,
        "platform_client",
    )
    await toolkit.record_metric(
        "tenants_mapped",
        float(len(mappings)),
    )

    return {
        "tenant_mappings": mappings,
        "stage": MTIGStage.SCAN_BOUNDARIES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "map_tenants",
        "session_start": start,
    }


async def scan_boundaries(
    state: MultiTenantIsolationGuardState,
) -> dict[str, Any]:
    """Scan tenant isolation boundaries."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    scans = await toolkit.scan_boundaries(
        state.tenant_mappings,
    )
    degraded = sum(1 for s in scans if s.get("status") == "degraded")

    try:
        ctx = _json.dumps(
            {
                "tenants": len(state.tenant_mappings),
                "scans": len(scans),
                "degraded": degraded,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_SCAN,
            user_prompt=f"Boundary scan context:\n{ctx}",
            schema=BoundaryScanOutput,
        )
        if hasattr(llm_result, "boundaries_scanned"):
            logger.info(
                "llm_enhanced",
                node="scan_boundaries",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="scan_boundaries",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "scan_boundaries",
        f"scanning {len(state.tenant_mappings)} tenants",
        f"{len(scans)} scans, {degraded} degraded",
        elapsed,
        "network_scanner",
    )

    return {
        "boundary_scans": scans,
        "stage": MTIGStage.DETECT_LEAKAGE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "scan_boundaries",
    }


async def detect_leakage(
    state: MultiTenantIsolationGuardState,
) -> dict[str, Any]:
    """Detect cross-tenant data leakage."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    leakages = await toolkit.detect_leakage(
        state.boundary_scans,
        state.tenant_mappings,
    )
    critical = sum(
        1
        for l in leakages  # noqa: E741
        if l.get("severity") == "critical"
    )

    try:
        ctx = _json.dumps(
            {
                "scans": len(state.boundary_scans),
                "leakages": len(leakages),
                "critical": critical,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_LEAKAGE,
            user_prompt=f"Leakage detection context:\n{ctx}",
            schema=LeakageOutput,
        )
        if hasattr(llm_result, "leakages_detected"):
            logger.info(
                "llm_enhanced",
                node="detect_leakage",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_leakage",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "detect_leakage",
        f"checking {len(state.boundary_scans)} scans",
        f"{len(leakages)} leakages, {critical} critical",
        elapsed,
        "network_scanner",
    )
    await toolkit.record_metric(
        "leakages_detected",
        float(len(leakages)),
    )

    return {
        "leakage_detections": leakages,
        "stage": MTIGStage.ASSESS_ISOLATION,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_leakage",
    }


async def assess_isolation(
    state: MultiTenantIsolationGuardState,
) -> dict[str, Any]:
    """Assess overall isolation quality."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments = await toolkit.assess_isolation(
        state.boundary_scans,
        state.leakage_detections,
    )
    non_compliant = sum(1 for a in assessments if a.get("compliance_status") == "non_compliant")

    try:
        ctx = _json.dumps(
            {
                "scans": len(state.boundary_scans),
                "assessments": len(assessments),
                "non_compliant": non_compliant,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ASSESS,
            user_prompt=f"Isolation assessment context:\n{ctx}",
            schema=AssessmentOutput,
        )
        if hasattr(llm_result, "assessments_completed"):
            logger.info(
                "llm_enhanced",
                node="assess_isolation",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_isolation",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "assess_isolation",
        f"assessing {len(state.boundary_scans)} boundaries",
        (f"{len(assessments)} assessed, {non_compliant} non-compliant"),
        elapsed,
        "policy_engine",
    )

    return {
        "isolation_assessments": assessments,
        "stage": MTIGStage.ENFORCE_CONTROLS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_isolation",
    }


async def enforce_controls(
    state: MultiTenantIsolationGuardState,
) -> dict[str, Any]:
    """Enforce isolation controls."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    enforcements = await toolkit.enforce_controls(
        state.isolation_assessments,
    )

    try:
        ctx = _json.dumps(
            {
                "assessments": len(
                    state.isolation_assessments,
                ),
                "enforcements": len(enforcements),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ENFORCE,
            user_prompt=f"Enforcement context:\n{ctx}",
            schema=EnforcementOutput,
        )
        if hasattr(llm_result, "controls_enforced"):
            logger.info(
                "llm_enhanced",
                node="enforce_controls",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="enforce_controls",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "enforce_controls",
        (f"enforcing for {len(state.isolation_assessments)} assessments"),
        f"{len(enforcements)} controls enforced",
        elapsed,
        "policy_engine",
    )
    await toolkit.record_metric(
        "controls_enforced",
        float(len(enforcements)),
    )

    return {
        "control_enforcements": enforcements,
        "stage": MTIGStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "enforce_controls",
    }


async def generate_report(
    state: MultiTenantIsolationGuardState,
) -> dict[str, Any]:
    """Generate final isolation guard report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int(
            (datetime.now(UTC) - state.session_start).total_seconds() * 1000,
        )

    report = {
        "request_id": state.request_id,
        "tenants_mapped": len(state.tenant_mappings),
        "boundaries_scanned": len(state.boundary_scans),
        "leakages_detected": len(state.leakage_detections),
        "assessments": len(state.isolation_assessments),
        "controls_enforced": len(state.control_enforcements),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric(
        "scan_duration_ms",
        float(duration_ms),
    )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "generate_report",
        f"finalizing {state.request_id}",
        f"report complete in {duration_ms}ms",
        elapsed,
        None,
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
