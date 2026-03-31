"""Node implementations for the API Schema Validator."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.api_schema_validator.models import (
    APISchemaValidatorState,
    ASVStage,
    ReasoningStep,
)
from shieldops.agents.api_schema_validator.prompts import (
    SYSTEM_BREAKING,
    SYSTEM_DISCOVER,
    SYSTEM_FIXES,
    SYSTEM_IMPACT,
    SYSTEM_VALIDATE,
    BreakingChangeOutput,
    ContractValidationOutput,
    FixGenerationOutput,
    ImpactOutput,
    SchemaDiscoveryOutput,
)
from shieldops.agents.api_schema_validator.tools import (
    APISchemaValidatorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: APISchemaValidatorToolkit | None = None


def set_toolkit(
    toolkit: APISchemaValidatorToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> APISchemaValidatorToolkit:
    if _toolkit is None:
        return APISchemaValidatorToolkit()
    return _toolkit


def _step(
    state: APISchemaValidatorState,
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


async def discover_schemas(
    state: APISchemaValidatorState,
) -> dict[str, Any]:
    """Discover API schemas across services."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.discover_schemas(state.config)
    total_ep = sum(s.get("endpoint_count", 0) for s in raw)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "scope": state.config.get("scope", ""),
                "services": state.config.get("services", [])[:10],
                "schema_count": len(raw),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_DISCOVER,
            user_prompt=(f"Schema discovery context:\n{ctx}"),
            schema=SchemaDiscoveryOutput,
        )
        if hasattr(llm_result, "total_endpoints") and llm_result.total_endpoints > total_ep:
            total_ep = llm_result.total_endpoints
        logger.info(
            "llm_enhanced",
            node="discover_schemas",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="discover_schemas",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "discover_schemas",
        f"scope={state.config.get('scope', '')}",
        f"found {len(raw)} schemas, {total_ep} endpoints",
        elapsed,
        "schema_registry",
    )
    await toolkit.record_metric("discovery", float(len(raw)))

    return {
        "discovered_schemas": raw,
        "total_endpoints": total_ep,
        "stage": ASVStage.VALIDATE_CONTRACTS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "discover_schemas",
        "session_start": start,
    }


async def validate_contracts(
    state: APISchemaValidatorState,
) -> dict[str, Any]:
    """Validate contracts for discovered schemas."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    violations = await toolkit.validate_contracts(
        state.discovered_schemas,
    )
    v_count = len(violations)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "schema_count": len(state.discovered_schemas),
                "violations": violations[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_VALIDATE,
            user_prompt=(f"Contract validation:\n{ctx}"),
            schema=ContractValidationOutput,
        )
        if hasattr(llm_result, "violations_found") and llm_result.violations_found > v_count:
            v_count = llm_result.violations_found
        logger.info(
            "llm_enhanced",
            node="validate_contracts",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="validate_contracts",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "validate_contracts",
        f"validating {len(state.discovered_schemas)} schemas",
        f"{v_count} violations found",
        elapsed,
        "contract_engine",
    )

    return {
        "contract_violations": violations,
        "violation_count": v_count,
        "stage": ASVStage.DETECT_BREAKING,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "validate_contracts",
    }


async def detect_breaking(
    state: APISchemaValidatorState,
) -> dict[str, Any]:
    """Detect breaking changes between schema versions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    changes = await toolkit.detect_breaking_changes(
        state.discovered_schemas,
    )
    crit_count = sum(1 for c in changes if c.get("severity") == "critical")

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "schema_count": len(state.discovered_schemas),
                "changes": changes[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_BREAKING,
            user_prompt=(f"Breaking change detection:\n{ctx}"),
            schema=BreakingChangeOutput,
        )
        if hasattr(llm_result, "critical_breaking") and llm_result.critical_breaking > crit_count:
            crit_count = llm_result.critical_breaking
        logger.info(
            "llm_enhanced",
            node="detect_breaking",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_breaking",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "detect_breaking",
        f"checking {len(state.discovered_schemas)} schemas",
        f"{len(changes)} breaking, {crit_count} critical",
        elapsed,
        "diff_engine",
    )
    await toolkit.record_metric(
        "breaking_changes",
        float(len(changes)),
    )

    return {
        "breaking_changes": changes,
        "critical_breaking_count": crit_count,
        "stage": ASVStage.ASSESS_IMPACT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "detect_breaking",
    }


async def assess_impact(
    state: APISchemaValidatorState,
) -> dict[str, Any]:
    """Assess impact of breaking changes."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments = await toolkit.assess_impact(
        state.breaking_changes,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "change_count": len(state.breaking_changes),
                "assessments": assessments[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_IMPACT,
            user_prompt=(f"Impact assessment:\n{ctx}"),
            schema=ImpactOutput,
        )
        if hasattr(llm_result, "total_affected_services"):
            logger.info(
                "llm_enhanced",
                node="assess_impact",
                affected=llm_result.total_affected_services,
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_impact",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "assess_impact",
        f"assessing {len(state.breaking_changes)} changes",
        f"{len(assessments)} impact assessments",
        elapsed,
        "impact_analyzer",
    )

    return {
        "impact_assessments": assessments,
        "stage": ASVStage.GENERATE_FIXES,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "assess_impact",
    }


async def generate_fixes(
    state: APISchemaValidatorState,
) -> dict[str, Any]:
    """Generate fix suggestions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    fixes = await toolkit.generate_fixes(
        state.contract_violations,
        state.breaking_changes,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "violation_count": len(state.contract_violations),
                "change_count": len(state.breaking_changes),
                "fix_count": len(fixes),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_FIXES,
            user_prompt=(f"Fix generation context:\n{ctx}"),
            schema=FixGenerationOutput,
        )
        if hasattr(llm_result, "fixes"):
            logger.info(
                "llm_enhanced",
                node="generate_fixes",
                llm_fixes=len(llm_result.fixes),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_fixes",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "generate_fixes",
        f"generating fixes for {state.violation_count} violations",
        f"created {len(fixes)} fixes",
        elapsed,
        "fix_engine",
    )

    return {
        "suggested_fixes": fixes,
        "stage": ASVStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "generate_fixes",
    }


async def generate_report(
    state: APISchemaValidatorState,
) -> dict[str, Any]:
    """Generate final schema validation report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int(
            (datetime.now(UTC) - state.session_start).total_seconds() * 1000,
        )

    report = {
        "request_id": state.request_id,
        "total_schemas": len(state.discovered_schemas),
        "total_endpoints": state.total_endpoints,
        "violations": state.violation_count,
        "breaking_changes": len(state.breaking_changes),
        "critical_breaking": state.critical_breaking_count,
        "fixes_generated": len(state.suggested_fixes),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric(
        "scan_duration_ms",
        float(duration_ms),
    )
    await toolkit.record_metric(
        "total_schemas",
        float(len(state.discovered_schemas)),
    )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
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
