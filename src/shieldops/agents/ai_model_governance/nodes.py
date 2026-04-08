"""Node implementations for the AI Model Governance Agent."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.ai_model_governance.models import (
    AIModelGovernanceState,
    GovernanceStage,
    ReasoningStep,
)
from shieldops.agents.ai_model_governance.prompts import (
    SYSTEM_BIAS,
    SYSTEM_COMPLIANCE,
    SYSTEM_INVENTORY,
    SYSTEM_POLICY,
    SYSTEM_RISK,
    BiasCheckOutput,
    ComplianceOutput,
    InventoryOutput,
    PolicyOutput,
    RiskAssessmentOutput,
)
from shieldops.agents.ai_model_governance.tools import (
    AIModelGovernanceToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AIModelGovernanceToolkit | None = None


def _get_toolkit() -> AIModelGovernanceToolkit:
    if _toolkit is None:
        return AIModelGovernanceToolkit()
    return _toolkit


def _step(
    state: AIModelGovernanceState,
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


async def inventory_models(
    state: AIModelGovernanceState,
) -> dict[str, Any]:
    """Inventory AI models across the organization."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.inventory_models(state.governance_config)
    total = len(raw)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "scope": state.governance_config.get("scope", ""),
                "model_count": total,
                "sample": raw[:5],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_INVENTORY,
            user_prompt=f"Model inventory context:\n{ctx}",
            schema=InventoryOutput,
        )
        if hasattr(llm_result, "total_models") and llm_result.total_models > total:
            total = llm_result.total_models
        logger.info(
            "llm_enhanced",
            node="inventory_models",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="inventory_models",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "inventory_models",
        f"scope={state.governance_config.get('scope', '')}",
        f"found {total} models",
        elapsed,
        "model_registry",
    )
    await toolkit.record_metric("inventory_count", float(total))

    return {
        "model_inventory": raw,
        "total_models": total,
        "stage": GovernanceStage.ASSESS_RISK,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "inventory_models",
        "session_start": start,
    }


async def assess_risk(
    state: AIModelGovernanceState,
) -> dict[str, Any]:
    """Assess risk for each inventoried model."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments = await toolkit.assess_risk(state.model_inventory)
    high_count = sum(1 for a in assessments if a.get("risk_tier") in ("high", "unacceptable"))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "model_count": len(state.model_inventory),
                "assessments": assessments[:5],
                "high_risk": high_count,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_RISK,
            user_prompt=f"Risk assessment context:\n{ctx}",
            schema=RiskAssessmentOutput,
        )
        if hasattr(llm_result, "high_risk_count") and llm_result.high_risk_count > high_count:
            high_count = llm_result.high_risk_count
        logger.info(
            "llm_enhanced",
            node="assess_risk",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_risk",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "assess_risk",
        f"assessing {len(state.model_inventory)} models",
        f"{high_count} high-risk models",
        elapsed,
        "risk_engine",
    )

    return {
        "risk_assessments": assessments,
        "high_risk_count": high_count,
        "stage": GovernanceStage.CHECK_BIAS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "assess_risk",
    }


async def check_bias(
    state: AIModelGovernanceState,
) -> dict[str, Any]:
    """Check models for bias across protected groups."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    reports = await toolkit.check_bias(
        state.model_inventory,
        state.risk_assessments,
    )
    bias_count = sum(1 for r in reports if not r.get("passed", True))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "model_count": len(state.model_inventory),
                "bias_reports": reports[:5],
                "bias_detected": bias_count,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_BIAS,
            user_prompt=f"Bias detection context:\n{ctx}",
            schema=BiasCheckOutput,
        )
        if hasattr(llm_result, "bias_detected") and llm_result.bias_detected > bias_count:
            bias_count = llm_result.bias_detected
        logger.info(
            "llm_enhanced",
            node="check_bias",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="check_bias",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "check_bias",
        f"scanning {len(state.model_inventory)} models for bias",
        f"{bias_count} models with bias detected",
        elapsed,
        "bias_scanner",
    )

    return {
        "bias_reports": reports,
        "bias_detected_count": bias_count,
        "stage": GovernanceStage.VALIDATE_COMPLIANCE,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "check_bias",
    }


async def validate_compliance(
    state: AIModelGovernanceState,
) -> dict[str, Any]:
    """Validate models against regulatory frameworks."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.validate_compliance(
        state.model_inventory,
        state.risk_assessments,
    )
    non_compliant = sum(1 for r in results if not r.get("compliant", True))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "model_count": len(state.model_inventory),
                "compliance_results": results[:5],
                "non_compliant": non_compliant,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_COMPLIANCE,
            user_prompt=f"Compliance validation:\n{ctx}",
            schema=ComplianceOutput,
        )
        if hasattr(llm_result, "non_compliant") and llm_result.non_compliant > non_compliant:
            non_compliant = llm_result.non_compliant
        logger.info(
            "llm_enhanced",
            node="validate_compliance",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="validate_compliance",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "validate_compliance",
        f"validating {len(state.model_inventory)} models",
        f"{non_compliant} non-compliant",
        elapsed,
        "compliance_engine",
    )

    return {
        "compliance_results": results,
        "non_compliant_count": non_compliant,
        "stage": GovernanceStage.ENFORCE_POLICY,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "validate_compliance",
    }


async def enforce_policy(
    state: AIModelGovernanceState,
) -> dict[str, Any]:
    """Enforce governance policies on non-compliant models."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    actions = await toolkit.enforce_policy(
        state.model_inventory,
        state.compliance_results,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "non_compliant": state.non_compliant_count,
                "actions": actions[:5],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_POLICY,
            user_prompt=f"Policy enforcement context:\n{ctx}",
            schema=PolicyOutput,
        )
        if hasattr(llm_result, "enforced_count"):
            logger.info(
                "llm_enhanced",
                node="enforce_policy",
                enforced=llm_result.enforced_count,
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="enforce_policy",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "enforce_policy",
        f"enforcing policies on {state.non_compliant_count} models",
        f"{len(actions)} actions taken",
        elapsed,
        "policy_engine",
    )

    return {
        "policy_actions": actions,
        "stage": GovernanceStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "enforce_policy",
    }


async def generate_report(
    state: AIModelGovernanceState,
) -> dict[str, Any]:
    """Generate final governance report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report = {
        "request_id": state.request_id,
        "total_models": state.total_models,
        "high_risk_count": state.high_risk_count,
        "bias_detected": state.bias_detected_count,
        "non_compliant": state.non_compliant_count,
        "policy_actions": len(state.policy_actions),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric(
        "governance_duration_ms",
        float(duration_ms),
    )
    await toolkit.record_metric(
        "total_models",
        float(state.total_models),
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "generate_report",
        f"finalizing governance {state.request_id}",
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
