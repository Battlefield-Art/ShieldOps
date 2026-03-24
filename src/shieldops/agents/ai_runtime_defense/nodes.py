"""AI Runtime Defense Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    DefenseStage,
)
from .tools import AIRuntimeDefenseToolkit

logger = structlog.get_logger()

# Module-level toolkit reference for node functions
_toolkit: AIRuntimeDefenseToolkit | None = None


def set_toolkit(toolkit: AIRuntimeDefenseToolkit) -> None:
    """Set the module-level toolkit for node functions."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> AIRuntimeDefenseToolkit:
    """Get the module-level toolkit, creating a default if needed."""
    global _toolkit
    if _toolkit is None:
        _toolkit = AIRuntimeDefenseToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def scan_prompts(state: dict[str, Any], toolkit: AIRuntimeDefenseToolkit) -> dict[str, Any]:
    """Scan prompt pipeline for injection attacks."""
    logger.info("ai_runtime_defense.node.scan_prompts")
    state = _to_dict(state)

    app_id = state.get("app_id", "unknown")
    deployment_ctx = state.get("deployment_context", {})
    prompts = deployment_ctx.get("prompts", [])

    findings = await toolkit.scan_prompt_pipeline(app_id, prompts)
    findings_data = [f.model_dump() for f in findings]

    reasoning_note = f"Scanned {len(prompts)} prompts, found {len(findings)} injection attempts"

    # LLM enhancement: deeper injection analysis
    try:
        from .prompts import SYSTEM_PROMPT_INJECTION_ANALYSIS, PromptInjectionOutput

        context_json = json.dumps(
            {
                "app_id": app_id,
                "prompts_scanned": len(prompts),
                "findings_count": len(findings),
                "findings_summary": [
                    {
                        "type": f.injection_type,
                        "severity": f.severity,
                        "confidence": f.confidence,
                    }
                    for f in findings[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            PromptInjectionOutput,
            await llm_structured(
                system_prompt=SYSTEM_PROMPT_INJECTION_ANALYSIS,
                user_prompt=f"Prompt injection analysis context:\n{context_json}",
                schema=PromptInjectionOutput,
            ),
        )
        logger.info("llm_enhanced", agent="ai_runtime_defense", node="scan_prompts")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="ai_runtime_defense", node="scan_prompts")

    return {
        "stage": DefenseStage.DETECT_EXFILTRATION.value,
        "prompt_injection_findings": findings_data,
        "current_step": "scan_prompts",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def detect_exfiltration(
    state: dict[str, Any], toolkit: AIRuntimeDefenseToolkit
) -> dict[str, Any]:
    """Analyze model outputs for data leakage."""
    logger.info("ai_runtime_defense.node.detect_exfiltration")
    state = _to_dict(state)

    app_id = state.get("app_id", "unknown")
    deployment_ctx = state.get("deployment_context", {})
    outputs = deployment_ctx.get("outputs", [])

    attempts = await toolkit.analyze_model_outputs(app_id, outputs)
    attempts_data = [a.model_dump() for a in attempts]

    reasoning_note = (
        f"Analyzed {len(outputs)} model outputs, detected {len(attempts)} exfiltration attempts"
    )

    # LLM enhancement: deeper exfiltration analysis
    try:
        from .prompts import SYSTEM_EXFILTRATION_DETECTION, ExfiltrationOutput

        context_json = json.dumps(
            {
                "app_id": app_id,
                "outputs_analyzed": len(outputs),
                "attempts_found": len(attempts),
                "attempts_summary": [
                    {
                        "channel": a.channel,
                        "classification": a.data_classification,
                        "severity": a.severity,
                    }
                    for a in attempts[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ExfiltrationOutput,
            await llm_structured(
                system_prompt=SYSTEM_EXFILTRATION_DETECTION,
                user_prompt=f"Exfiltration detection context:\n{context_json}",
                schema=ExfiltrationOutput,
            ),
        )
        logger.info("llm_enhanced", agent="ai_runtime_defense", node="detect_exfiltration")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="ai_runtime_defense", node="detect_exfiltration")

    return {
        "stage": DefenseStage.DETECT_ABUSE.value,
        "exfiltration_attempts": attempts_data,
        "current_step": "detect_exfiltration",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def detect_model_abuse(
    state: dict[str, Any], toolkit: AIRuntimeDefenseToolkit
) -> dict[str, Any]:
    """Identify model abuse patterns."""
    logger.info("ai_runtime_defense.node.detect_model_abuse")
    state = _to_dict(state)

    app_id = state.get("app_id", "unknown")
    deployment_ctx = state.get("deployment_context", {})
    usage_logs = deployment_ctx.get("usage_logs", [])

    incidents = await toolkit.audit_model_usage(app_id, usage_logs)
    incidents_data = [i.model_dump() for i in incidents]

    reasoning_note = f"Audited {len(usage_logs)} usage logs, found {len(incidents)} abuse incidents"

    # LLM enhancement: deeper abuse detection
    try:
        from .prompts import SYSTEM_MODEL_ABUSE_DETECTION, AbuseDetectionOutput

        context_json = json.dumps(
            {
                "app_id": app_id,
                "logs_audited": len(usage_logs),
                "incidents_found": len(incidents),
                "incidents_summary": [
                    {
                        "type": i.abuse_type,
                        "severity": i.severity,
                        "user_id": i.user_id,
                    }
                    for i in incidents[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            AbuseDetectionOutput,
            await llm_structured(
                system_prompt=SYSTEM_MODEL_ABUSE_DETECTION,
                user_prompt=f"Model abuse detection context:\n{context_json}",
                schema=AbuseDetectionOutput,
            ),
        )
        logger.info("llm_enhanced", agent="ai_runtime_defense", node="detect_model_abuse")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="ai_runtime_defense", node="detect_model_abuse")

    return {
        "stage": DefenseStage.SCAN_SUPPLY_CHAIN.value,
        "model_abuse_incidents": incidents_data,
        "current_step": "detect_model_abuse",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def scan_supply_chain(
    state: dict[str, Any], toolkit: AIRuntimeDefenseToolkit
) -> dict[str, Any]:
    """Check AI component supply chain for risks."""
    logger.info("ai_runtime_defense.node.scan_supply_chain")
    state = _to_dict(state)

    app_id = state.get("app_id", "unknown")
    deployment_ctx = state.get("deployment_context", {})
    dependencies = deployment_ctx.get("dependencies", [])

    risks = await toolkit.check_supply_chain(app_id, dependencies)
    risks_data = [r.model_dump() for r in risks]

    return {
        "stage": DefenseStage.GENERATE_POLICIES.value,
        "supply_chain_risks": risks_data,
        "current_step": "scan_supply_chain",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Scanned {len(dependencies)} AI components, found {len(risks)} supply chain risks"],
    }


async def generate_policies(
    state: dict[str, Any], toolkit: AIRuntimeDefenseToolkit
) -> dict[str, Any]:
    """Generate firewall and access policies from findings."""
    logger.info("ai_runtime_defense.node.generate_policies")
    state = _to_dict(state)

    findings = {
        "injections": state.get("prompt_injection_findings", []),
        "exfiltrations": state.get("exfiltration_attempts", []),
        "abuse": state.get("model_abuse_incidents", []),
    }

    rules = await toolkit.generate_firewall_rules(findings)
    rules_data = [r.model_dump() for r in rules]

    reasoning_note = f"Generated {len(rules)} firewall rules from security findings"

    # LLM enhancement: generate comprehensive policies
    try:
        from .prompts import SYSTEM_POLICY_GENERATION, PolicyOutput

        context_json = json.dumps(
            {
                "injection_count": len(findings["injections"]),
                "exfil_count": len(findings["exfiltrations"]),
                "abuse_count": len(findings["abuse"]),
                "supply_chain_risks": len(state.get("supply_chain_risks", [])),
                "rules_generated": len(rules),
            },
            default=str,
        )
        llm_result = cast(
            PolicyOutput,
            await llm_structured(
                system_prompt=SYSTEM_POLICY_GENERATION,
                user_prompt=f"Policy generation context:\n{context_json}",
                schema=PolicyOutput,
            ),
        )
        logger.info("llm_enhanced", agent="ai_runtime_defense", node="generate_policies")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
        policy_recs = llm_result.access_policies + llm_result.monitoring_recommendations
    except Exception:
        logger.debug("llm_fallback", agent="ai_runtime_defense", node="generate_policies")
        policy_recs = []

    existing_recs = state.get("policy_recommendations", [])

    return {
        "stage": DefenseStage.EXECUTE_RESPONSE.value,
        "firewall_rules_generated": rules_data,
        "policy_recommendations": existing_recs + policy_recs,
        "current_step": "generate_policies",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def execute_response(
    state: dict[str, Any], toolkit: AIRuntimeDefenseToolkit
) -> dict[str, Any]:
    """Apply protective measures (credential rotation, firewall enforcement)."""
    logger.info("ai_runtime_defense.node.execute_response")
    state = _to_dict(state)

    app_id = state.get("app_id", "unknown")

    # Rotate credentials if critical findings exist
    injections = state.get("prompt_injection_findings", [])
    exfils = state.get("exfiltration_attempts", [])
    has_critical = any(f.get("severity") == "critical" for f in injections) or any(
        e.get("severity") == "critical" for e in exfils
    )

    rotated: list[str] = []
    if has_critical:
        rotated = await toolkit.rotate_credentials(app_id)

    return {
        "stage": DefenseStage.REPORT.value,
        "credential_rotations": rotated,
        "current_step": "execute_response",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Executed response: {'rotated credentials' if rotated else 'no rotation needed'}, "
            f"applied {len(state.get('firewall_rules_generated', []))} firewall rules"
        ],
    }


async def generate_report(
    state: dict[str, Any], toolkit: AIRuntimeDefenseToolkit
) -> dict[str, Any]:
    """Summarize all findings into final report."""
    logger.info("ai_runtime_defense.node.generate_report")
    state = _to_dict(state)

    session_start = state.get("session_start", 0.0)
    duration = (time.time() - session_start) * 1000 if session_start > 0 else 0.0

    total_findings = (
        len(state.get("prompt_injection_findings", []))
        + len(state.get("exfiltration_attempts", []))
        + len(state.get("model_abuse_incidents", []))
        + len(state.get("supply_chain_risks", []))
    )

    return {
        "stage": DefenseStage.REPORT.value,
        "session_duration_ms": round(duration, 2),
        "current_step": "report",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"AI Runtime Defense scan complete: {total_findings} total findings, "
            f"{len(state.get('firewall_rules_generated', []))} rules generated, "
            f"{len(state.get('credential_rotations', []))} credentials rotated"
        ],
    }
