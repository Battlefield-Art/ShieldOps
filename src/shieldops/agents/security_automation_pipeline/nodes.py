"""Node implementations for the Security Automation Pipeline."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.security_automation_pipeline.models import (
    ReasoningStep,
    SAPStage,
    SecurityAutomationPipelineState,
)
from shieldops.agents.security_automation_pipeline.prompts import (
    SYSTEM_CHECK,
    SYSTEM_ENFORCE,
    SYSTEM_EVALUATE,
    SYSTEM_INJECT,
    SYSTEM_SCAN,
    CheckResultsOutput,
    EnforcementOutput,
    EvaluationOutput,
    GateInjectionOutput,
    PipelineScanOutput,
)
from shieldops.agents.security_automation_pipeline.tools import (
    SecurityAutomationPipelineToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SecurityAutomationPipelineToolkit | None = None


def set_toolkit(
    toolkit: SecurityAutomationPipelineToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> SecurityAutomationPipelineToolkit:
    if _toolkit is None:
        return SecurityAutomationPipelineToolkit()
    return _toolkit


def _step(
    state: SecurityAutomationPipelineState,
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


async def scan_pipeline(
    state: SecurityAutomationPipelineState,
) -> dict[str, Any]:
    """Scan CI/CD pipeline configurations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.scan_pipeline(state.config)
    scanned = len(raw)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "scope": state.config.get("scope", ""),
                "repositories": state.config.get("repositories", [])[:10],
                "pipeline_count": scanned,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_SCAN,
            user_prompt=(f"Pipeline scan context:\n{ctx}"),
            schema=PipelineScanOutput,
        )
        if hasattr(llm_result, "pipelines_found"):
            logger.info(
                "llm_enhanced",
                node="scan_pipeline",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="scan_pipeline",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "scan_pipeline",
        f"scope={state.config.get('scope', '')}",
        f"scanned {scanned} pipelines",
        elapsed,
        "ci_provider",
    )
    await toolkit.record_metric("pipelines_scanned", float(scanned))

    return {
        "pipeline_scans": raw,
        "pipelines_scanned": scanned,
        "stage": SAPStage.INJECT_GATES,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "scan_pipeline",
        "session_start": start,
    }


async def inject_gates(
    state: SecurityAutomationPipelineState,
) -> dict[str, Any]:
    """Inject security gates into pipelines."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    gates = await toolkit.inject_security_gates(
        state.pipeline_scans,
    )
    injected = len(gates)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "pipeline_count": len(state.pipeline_scans),
                "gates": gates[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_INJECT,
            user_prompt=(f"Gate injection context:\n{ctx}"),
            schema=GateInjectionOutput,
        )
        if hasattr(llm_result, "gates_injected"):
            logger.info(
                "llm_enhanced",
                node="inject_gates",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="inject_gates",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "inject_gates",
        f"injecting gates for {len(state.pipeline_scans)} pipelines",
        f"{injected} gates injected",
        elapsed,
        "gate_injector",
    )

    return {
        "security_gates": gates,
        "gates_injected": injected,
        "stage": SAPStage.RUN_CHECKS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "inject_gates",
    }


async def run_checks(
    state: SecurityAutomationPipelineState,
) -> dict[str, Any]:
    """Run security checks for injected gates."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.run_security_checks(
        state.security_gates,
    )
    total = sum(r.get("findings_count", 0) for r in results)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "gate_count": len(state.security_gates),
                "results": results[:10],
                "total_findings": total,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CHECK,
            user_prompt=(f"Security check results:\n{ctx}"),
            schema=CheckResultsOutput,
        )
        if hasattr(llm_result, "total_findings") and llm_result.total_findings > total:
            total = llm_result.total_findings
        logger.info(
            "llm_enhanced",
            node="run_checks",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="run_checks",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "run_checks",
        f"running {len(state.security_gates)} checks",
        f"{total} total findings",
        elapsed,
        "security_scanner",
    )
    await toolkit.record_metric("total_findings", float(total))

    return {
        "check_results": results,
        "total_findings": total,
        "stage": SAPStage.EVALUATE_RESULTS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "run_checks",
    }


async def evaluate_results(
    state: SecurityAutomationPipelineState,
) -> dict[str, Any]:
    """Evaluate check results against gate policies."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    evaluations = await toolkit.evaluate_results(
        state.check_results,
    )
    passed = sum(1 for e in evaluations if e.get("passed"))
    failed = len(evaluations) - passed

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "result_count": len(state.check_results),
                "evaluations": evaluations[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_EVALUATE,
            user_prompt=(f"Gate evaluation context:\n{ctx}"),
            schema=EvaluationOutput,
        )
        if hasattr(llm_result, "gates_passed"):
            logger.info(
                "llm_enhanced",
                node="evaluate_results",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="evaluate_results",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "evaluate_results",
        f"evaluating {len(state.check_results)} results",
        f"{passed} passed, {failed} failed",
        elapsed,
        "policy_engine",
    )

    return {
        "gate_evaluations": evaluations,
        "gates_passed": passed,
        "gates_failed": failed,
        "stage": SAPStage.ENFORCE_GATES,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "evaluate_results",
    }


async def enforce_gates(
    state: SecurityAutomationPipelineState,
) -> dict[str, Any]:
    """Enforce gate decisions on pipelines."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    actions = await toolkit.enforce_gates(
        state.gate_evaluations,
        state.pipeline_scans,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "evaluation_count": len(state.gate_evaluations),
                "actions": actions[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ENFORCE,
            user_prompt=(f"Enforcement context:\n{ctx}"),
            schema=EnforcementOutput,
        )
        if hasattr(llm_result, "actions"):
            logger.info(
                "llm_enhanced",
                node="enforce_gates",
                llm_actions=len(llm_result.actions),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="enforce_gates",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "enforce_gates",
        f"enforcing {len(state.gate_evaluations)} evaluations",
        f"{len(actions)} enforcement actions",
        elapsed,
        "enforcement_engine",
    )

    return {
        "enforcement_actions": actions,
        "stage": SAPStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "enforce_gates",
    }


async def generate_report(
    state: SecurityAutomationPipelineState,
) -> dict[str, Any]:
    """Generate final security automation report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int(
            (datetime.now(UTC) - state.session_start).total_seconds() * 1000,
        )

    report = {
        "request_id": state.request_id,
        "pipelines_scanned": state.pipelines_scanned,
        "gates_injected": state.gates_injected,
        "total_findings": state.total_findings,
        "gates_passed": state.gates_passed,
        "gates_failed": state.gates_failed,
        "enforcement_actions": len(state.enforcement_actions),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric(
        "scan_duration_ms",
        float(duration_ms),
    )
    await toolkit.record_metric(
        "pipelines_scanned",
        float(state.pipelines_scanned),
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
