"""Node implementations for the LLM Prompt Firewall
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.llm_prompt_firewall.models import (
    LLMPromptFirewallState,
    LPFStage,
    ReasoningStep,
)
from shieldops.agents.llm_prompt_firewall.prompts import (
    SYSTEM_INJECTION,
    SYSTEM_INTENT,
    SYSTEM_REPORT,
    SYSTEM_RISK,
    FirewallReportOutput,
    InjectionDetectionOutput,
    IntentAnalysisOutput,
    RiskClassificationOutput,
)
from shieldops.agents.llm_prompt_firewall.tools import (
    LLMPromptFirewallToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: LLMPromptFirewallToolkit | None = None


def set_toolkit(
    toolkit: LLMPromptFirewallToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> LLMPromptFirewallToolkit:
    if _toolkit is None:
        return LLMPromptFirewallToolkit()
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
# Node: intercept_prompt
# ------------------------------------------------------------------


async def intercept_prompt(
    state: LLMPromptFirewallState,
) -> dict[str, Any]:
    """Intercept prompts from agent pipelines for
    security analysis."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    intercepted = await toolkit.intercept_prompt(
        prompts=state.prompts,
    )

    step = _step(
        state.reasoning_chain,
        "intercept_prompt",
        f"Intercepting {len(state.prompts)} prompts",
        f"Intercepted {len(intercepted)} prompts",
        start,
        "interceptor",
    )

    return {
        "intercepted": intercepted,
        "total_intercepted": len(intercepted),
        "stage": LPFStage.INTERCEPT_PROMPT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "intercept_prompt",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: analyze_intent
# ------------------------------------------------------------------


async def analyze_intent(
    state: LLMPromptFirewallState,
) -> dict[str, Any]:
    """Analyze prompt intent to detect manipulation."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    analyses = await toolkit.analyze_intent(
        intercepted=state.intercepted,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "intercepted_count": len(state.intercepted),
                "prompts_sample": state.intercepted[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_INTENT,
            user_prompt=f"Analyze intent:\n{ctx}",
            schema=IntentAnalysisOutput,
        )
        if llm_out.intents:  # type: ignore[union-attr]
            analyses = [
                *analyses,
                *llm_out.intents,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="analyze_intent",
            mismatches=llm_out.mismatches,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_intent",
        )

    step = _step(
        state.reasoning_chain,
        "analyze_intent",
        f"Analyzing {len(state.intercepted)} prompts",
        f"Produced {len(analyses)} intent analyses",
        start,
        "intent_analyzer",
    )

    return {
        "intent_analyses": analyses,
        "stage": LPFStage.ANALYZE_INTENT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_intent",
    }


# ------------------------------------------------------------------
# Node: detect_injection
# ------------------------------------------------------------------


async def detect_injection(
    state: LLMPromptFirewallState,
) -> dict[str, Any]:
    """Detect injection patterns in intercepted prompts."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    detections = await toolkit.detect_injection(
        prompts=state.intercepted,
        known_patterns=state.known_patterns,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "prompts_sample": state.intercepted[:5],
                "intent_results": state.intent_analyses[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_INJECTION,
            user_prompt=f"Detect injections:\n{ctx}",
            schema=InjectionDetectionOutput,
        )
        if llm_out.injections:  # type: ignore[union-attr]
            rand_id = random.randint(1000, 9999)  # noqa: S311
            for inj in llm_out.injections:  # type: ignore[union-attr]
                detections.append(
                    {
                        "detection_id": f"llm-{rand_id}",
                        "type": inj.get("type", "direct"),
                        "confidence": inj.get("confidence", "0.5"),
                        "payload": inj.get("payload", ""),
                    }
                )
        logger.info(
            "llm_enhanced",
            node="detect_injection",
            count=llm_out.injection_count,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_injection",
        )

    injection_count = sum(1 for d in detections if d.get("is_injection", True))

    step = _step(
        state.reasoning_chain,
        "detect_injection",
        f"Scanning {len(state.intercepted)} prompts",
        f"Detected {injection_count} injections",
        start,
        "injection_detector",
    )

    return {
        "detections": detections,
        "injections_detected": injection_count,
        "stage": LPFStage.DETECT_INJECTION,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_injection",
    }


# ------------------------------------------------------------------
# Node: classify_risk
# ------------------------------------------------------------------


async def classify_risk(
    state: LLMPromptFirewallState,
) -> dict[str, Any]:
    """Classify risk level for each analyzed prompt."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    classifications = await toolkit.classify_risk(
        detections=state.detections,
        intent_analyses=state.intent_analyses,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "detections": state.detections[:10],
                "intent_analyses": state.intent_analyses[:10],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_RISK,
            user_prompt=f"Classify risk:\n{ctx}",
            schema=RiskClassificationOutput,
        )
        if llm_out.factors:  # type: ignore[union-attr]
            classifications.append(
                {
                    "risk_level": llm_out.risk_level,  # type: ignore[union-attr]
                    "risk_score": llm_out.risk_score,  # type: ignore[union-attr]
                    "factors": llm_out.factors,  # type: ignore[union-attr]
                    "recommendation": llm_out.recommendation,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="classify_risk",
            risk=llm_out.risk_level,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="classify_risk",
        )

    step = _step(
        state.reasoning_chain,
        "classify_risk",
        f"Classifying {len(state.detections)} detections",
        f"Produced {len(classifications)} classifications",
        start,
        "risk_classifier",
    )

    return {
        "classifications": classifications,
        "stage": LPFStage.CLASSIFY_RISK,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "classify_risk",
    }


# ------------------------------------------------------------------
# Node: enforce_policy
# ------------------------------------------------------------------


async def enforce_policy(
    state: LLMPromptFirewallState,
) -> dict[str, Any]:
    """Enforce firewall policy on classified prompts."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    actions = await toolkit.enforce_policy(
        classifications=state.classifications,
        policy_config=state.policy_config,
    )

    blocked = sum(1 for a in actions if a.get("action_type") == "block")
    sanitized = sum(1 for a in actions if a.get("action_type") == "sanitize")

    step = _step(
        state.reasoning_chain,
        "enforce_policy",
        f"Enforcing on {len(state.classifications)} prompts",
        f"Blocked {blocked}, sanitized {sanitized}",
        start,
        "enforcer",
    )

    return {
        "actions": actions,
        "prompts_blocked": blocked,
        "prompts_sanitized": sanitized,
        "stage": LPFStage.ENFORCE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "enforce_policy",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: LLMPromptFirewallState,
) -> dict[str, Any]:
    """Generate the firewall activity report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report = await toolkit.generate_report(
        intercepted=state.intercepted,
        detections=state.detections,
        actions=state.actions,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "total_intercepted": state.total_intercepted,
                "injections_detected": state.injections_detected,
                "prompts_blocked": state.prompts_blocked,
                "prompts_sanitized": state.prompts_sanitized,
                "detections_sample": state.detections[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate report:\n{ctx}",
            schema=FirewallReportOutput,
        )
        if isinstance(llm_out, FirewallReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "attack_patterns": llm_out.attack_patterns,
                    "recommendations": llm_out.recommendations,
                    "effectiveness": llm_out.effectiveness_rating,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                patterns=len(llm_out.attack_patterns),
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
        metric_name="prompt_firewall_run",
        value=float(state.injections_detected),
        labels={"blocked": str(state.prompts_blocked)},
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.total_intercepted} prompts",
        f"Report generated, {state.injections_detected} injections",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": LPFStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
