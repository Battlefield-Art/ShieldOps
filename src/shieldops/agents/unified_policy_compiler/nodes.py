"""Node implementations for the Unified Policy Compiler."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.unified_policy_compiler.models import (
    ReasoningStep,
    UnifiedPolicyCompilerState,
    UPCStage,
)
from shieldops.agents.unified_policy_compiler.prompts import (
    SYSTEM_COMPILE,
    SYSTEM_CONFLICTS,
    SYSTEM_COVERAGE,
    SYSTEM_INGEST,
    SYSTEM_PARSE,
    CompileOutput,
    ConflictOutput,
    CoverageOutput,
    ParseOutput,
    PolicyIngestionOutput,
)
from shieldops.agents.unified_policy_compiler.tools import (
    UnifiedPolicyCompilerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: UnifiedPolicyCompilerToolkit | None = None


def set_toolkit(
    toolkit: UnifiedPolicyCompilerToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> UnifiedPolicyCompilerToolkit:
    if _toolkit is None:
        return UnifiedPolicyCompilerToolkit()
    return _toolkit


def _step(
    state: UnifiedPolicyCompilerState,
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


async def ingest_policies(
    state: UnifiedPolicyCompilerState,
) -> dict[str, Any]:
    """Ingest policies from frameworks."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    policies = await toolkit.ingest_policies(state.config)

    try:
        ctx = _json.dumps(
            {"count": len(policies)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_INGEST,
            user_prompt=f"Policy ingestion context:\n{ctx}",
            schema=PolicyIngestionOutput,
        )
        if hasattr(llm_result, "policies_ingested"):
            logger.info(
                "llm_enhanced",
                node="ingest_policies",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="ingest_policies",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "ingest_policies",
        f"config={state.config}",
        f"ingested {len(policies)} policies",
        elapsed,
        "policy_store",
    )
    await toolkit.record_metric(
        "policies_ingested",
        float(len(policies)),
    )

    return {
        "policy_records": policies,
        "stage": UPCStage.PARSE_REQUIREMENTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "ingest_policies",
        "session_start": start,
    }


async def parse_requirements(
    state: UnifiedPolicyCompilerState,
) -> dict[str, Any]:
    """Parse requirements from policies."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    parsed = await toolkit.parse_requirements(
        state.policy_records,
    )
    mandatory = sum(1 for p in parsed if p.get("mandatory"))

    try:
        ctx = _json.dumps(
            {
                "policies": len(state.policy_records),
                "parsed": len(parsed),
                "mandatory": mandatory,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_PARSE,
            user_prompt=f"Parse context:\n{ctx}",
            schema=ParseOutput,
        )
        if hasattr(llm_result, "requirements_parsed"):
            logger.info(
                "llm_enhanced",
                node="parse_requirements",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="parse_requirements",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "parse_requirements",
        f"parsing {len(state.policy_records)} policies",
        f"{len(parsed)} requirements, {mandatory} mandatory",
        elapsed,
        "policy_store",
    )

    return {
        "parsed_requirements": parsed,
        "stage": UPCStage.RESOLVE_CONFLICTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "parse_requirements",
    }


async def resolve_conflicts(
    state: UnifiedPolicyCompilerState,
) -> dict[str, Any]:
    """Resolve conflicts between requirements."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    conflicts = await toolkit.resolve_conflicts(
        state.parsed_requirements,
    )

    try:
        ctx = _json.dumps(
            {
                "requirements": len(
                    state.parsed_requirements,
                ),
                "conflicts": len(conflicts),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CONFLICTS,
            user_prompt=f"Conflict resolution context:\n{ctx}",
            schema=ConflictOutput,
        )
        if hasattr(llm_result, "conflicts_found"):
            logger.info(
                "llm_enhanced",
                node="resolve_conflicts",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="resolve_conflicts",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "resolve_conflicts",
        (f"checking {len(state.parsed_requirements)} requirements"),
        f"{len(conflicts)} conflicts found",
        elapsed,
        "compliance_engine",
    )
    await toolkit.record_metric(
        "conflicts_found",
        float(len(conflicts)),
    )

    return {
        "policy_conflicts": conflicts,
        "stage": UPCStage.COMPILE_RULESET,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "resolve_conflicts",
    }


async def compile_ruleset(
    state: UnifiedPolicyCompilerState,
) -> dict[str, Any]:
    """Compile unified ruleset."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    rules = await toolkit.compile_ruleset(
        state.parsed_requirements,
        state.policy_conflicts,
    )

    try:
        ctx = _json.dumps(
            {
                "requirements": len(
                    state.parsed_requirements,
                ),
                "rules": len(rules),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_COMPILE,
            user_prompt=f"Compilation context:\n{ctx}",
            schema=CompileOutput,
        )
        if hasattr(llm_result, "rules_compiled"):
            logger.info(
                "llm_enhanced",
                node="compile_ruleset",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="compile_ruleset",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "compile_ruleset",
        (f"compiling from {len(state.parsed_requirements)} requirements"),
        f"{len(rules)} rules compiled",
        elapsed,
        "opa_client",
    )

    return {
        "compiled_rules": rules,
        "stage": UPCStage.VALIDATE_COVERAGE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "compile_ruleset",
    }


async def validate_coverage(
    state: UnifiedPolicyCompilerState,
) -> dict[str, Any]:
    """Validate coverage against frameworks."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.validate_coverage(
        state.compiled_rules,
        state.policy_records,
    )

    try:
        ctx = _json.dumps(
            {
                "rules": len(state.compiled_rules),
                "frameworks_checked": len(results),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_COVERAGE,
            user_prompt=f"Coverage validation context:\n{ctx}",
            schema=CoverageOutput,
        )
        if hasattr(llm_result, "frameworks_checked"):
            logger.info(
                "llm_enhanced",
                node="validate_coverage",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="validate_coverage",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "validate_coverage",
        f"validating {len(state.compiled_rules)} rules",
        f"{len(results)} frameworks checked",
        elapsed,
        "compliance_engine",
    )
    await toolkit.record_metric(
        "frameworks_covered",
        float(len(results)),
    )

    return {
        "coverage_results": results,
        "stage": UPCStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "validate_coverage",
    }


async def generate_report(
    state: UnifiedPolicyCompilerState,
) -> dict[str, Any]:
    """Generate final compilation report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int(
            (datetime.now(UTC) - state.session_start).total_seconds() * 1000,
        )

    report = {
        "request_id": state.request_id,
        "policies_ingested": len(state.policy_records),
        "requirements_parsed": len(
            state.parsed_requirements,
        ),
        "conflicts_resolved": len(state.policy_conflicts),
        "rules_compiled": len(state.compiled_rules),
        "coverage_results": len(state.coverage_results),
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
