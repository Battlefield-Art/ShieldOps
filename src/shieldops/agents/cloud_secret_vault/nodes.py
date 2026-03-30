"""Node implementations for the Cloud Secret Vault."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.cloud_secret_vault.models import (
    CloudSecretVaultState,
    ReasoningStep,
    VaultStage,
)
from shieldops.agents.cloud_secret_vault.prompts import (
    SYSTEM_DISCOVER,
    SYSTEM_EXPOSURE,
    SYSTEM_REMEDIATE,
    SYSTEM_RISK,
    SYSTEM_ROTATION,
    ExposureCheckOutput,
    RemediationOutput,
    RiskAssessmentOutput,
    RotationAuditOutput,
    SecretDiscoveryOutput,
)
from shieldops.agents.cloud_secret_vault.tools import (
    CloudSecretVaultToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: CloudSecretVaultToolkit | None = None


def set_toolkit(
    toolkit: CloudSecretVaultToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> CloudSecretVaultToolkit:
    if _toolkit is None:
        return CloudSecretVaultToolkit()
    return _toolkit


def _step(
    state: CloudSecretVaultState,
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


async def discover_secrets(
    state: CloudSecretVaultState,
) -> dict[str, Any]:
    """Discover secrets across cloud vaults and environments."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.discover_secrets(state.scan_config)
    unmanaged = sum(1 for s in raw if not s.get("is_managed"))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "scope": state.scan_config.get("scope", "all"),
                "providers": state.scan_config.get("providers", [])[:10],
                "secret_count": len(raw),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_DISCOVER,
            user_prompt=(f"Secret discovery context:\n{ctx}"),
            schema=SecretDiscoveryOutput,
        )
        if hasattr(llm_result, "unmanaged_count") and llm_result.unmanaged_count > unmanaged:
            unmanaged = llm_result.unmanaged_count
        logger.info(
            "llm_enhanced",
            node="discover_secrets",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="discover_secrets",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "discover_secrets",
        f"scope={state.scan_config.get('scope', 'all')}",
        f"found {len(raw)} secrets, {unmanaged} unmanaged",
        elapsed,
        "vault_client",
    )
    await toolkit.record_metric("discovery", float(len(raw)))

    return {
        "discovered_secrets": raw,
        "unmanaged_count": unmanaged,
        "stage": VaultStage.AUDIT_ROTATION,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "discover_secrets",
        "session_start": start,
    }


async def audit_rotation(
    state: CloudSecretVaultState,
) -> dict[str, Any]:
    """Audit rotation compliance for discovered secrets."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    audits = await toolkit.audit_rotation(
        state.discovered_secrets,
    )
    overdue = sum(1 for a in audits if a.get("is_overdue"))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "secret_count": len(state.discovered_secrets),
                "audits": audits[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ROTATION,
            user_prompt=(f"Rotation audit context:\n{ctx}"),
            schema=RotationAuditOutput,
        )
        if hasattr(llm_result, "overdue_count") and llm_result.overdue_count > overdue:
            overdue = llm_result.overdue_count
        logger.info(
            "llm_enhanced",
            node="audit_rotation",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="audit_rotation",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "audit_rotation",
        f"auditing {len(state.discovered_secrets)} secrets",
        f"{overdue} overdue rotations",
        elapsed,
        "rotation_engine",
    )

    return {
        "rotation_audits": audits,
        "overdue_count": overdue,
        "stage": VaultStage.CHECK_EXPOSURE,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "audit_rotation",
    }


async def check_exposure(
    state: CloudSecretVaultState,
) -> dict[str, Any]:
    """Check for secret exposure in code, logs, and breaches."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    checks = await toolkit.check_exposure(
        state.discovered_secrets,
    )
    exposed = sum(1 for c in checks if c.get("is_exposed"))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "secret_count": len(state.discovered_secrets),
                "checks": checks[:10],
                "exposed_count": exposed,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_EXPOSURE,
            user_prompt=(f"Exposure check context:\n{ctx}"),
            schema=ExposureCheckOutput,
        )
        if hasattr(llm_result, "exposed_count") and llm_result.exposed_count > exposed:
            exposed = llm_result.exposed_count
        logger.info(
            "llm_enhanced",
            node="check_exposure",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="check_exposure",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "check_exposure",
        f"checking {len(state.discovered_secrets)} secrets",
        f"{exposed} exposed secrets",
        elapsed,
        "code_scanner",
    )
    await toolkit.record_metric("exposed_secrets", float(exposed))

    return {
        "exposure_checks": checks,
        "exposed_count": exposed,
        "stage": VaultStage.ASSESS_RISK,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "check_exposure",
    }


async def assess_risk(
    state: CloudSecretVaultState,
) -> dict[str, Any]:
    """Assess risk for secrets based on rotation and exposure."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments = await toolkit.assess_risk(
        state.rotation_audits,
        state.exposure_checks,
    )
    max_score = max(
        (a.get("risk_score", 0.0) for a in assessments),
        default=0.0,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "audit_count": len(state.rotation_audits),
                "exposure_count": len(state.exposure_checks),
                "assessments": assessments[:10],
                "max_score": max_score,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_RISK,
            user_prompt=(f"Risk assessment context:\n{ctx}"),
            schema=RiskAssessmentOutput,
        )
        if hasattr(llm_result, "max_risk_score") and llm_result.max_risk_score > max_score:
            max_score = round(
                (max_score + llm_result.max_risk_score) / 2,
                1,
            )
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
        f"assessing {len(state.rotation_audits)} audits + {len(state.exposure_checks)} exposures",
        f"max_risk={max_score}",
        elapsed,
        "risk_engine",
    )
    await toolkit.record_metric("max_risk", max_score)

    return {
        "risk_assessments": assessments,
        "max_risk_score": max_score,
        "stage": VaultStage.REMEDIATE,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "assess_risk",
    }


async def remediate_exposure(
    state: CloudSecretVaultState,
) -> dict[str, Any]:
    """Generate and apply remediation actions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    actions = await toolkit.remediate_exposure(
        state.risk_assessments,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "risk_count": len(state.risk_assessments),
                "action_count": len(actions),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REMEDIATE,
            user_prompt=(f"Remediation context:\n{ctx}"),
            schema=RemediationOutput,
        )
        if hasattr(llm_result, "actions"):
            logger.info(
                "llm_enhanced",
                node="remediate_exposure",
                llm_actions=len(llm_result.actions),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="remediate_exposure",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "remediate_exposure",
        f"remediating {len(state.risk_assessments)} risks",
        f"created {len(actions)} remediation actions",
        elapsed,
        "rotation_engine",
    )

    return {
        "remediations": actions,
        "stage": VaultStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "remediate_exposure",
    }


async def generate_report(
    state: CloudSecretVaultState,
) -> dict[str, Any]:
    """Generate final vault security report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report = {
        "request_id": state.request_id,
        "total_secrets": len(state.discovered_secrets),
        "unmanaged_count": state.unmanaged_count,
        "overdue_rotations": state.overdue_count,
        "exposed_secrets": state.exposed_count,
        "max_risk_score": state.max_risk_score,
        "remediations": len(state.remediations),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric("scan_duration_ms", float(duration_ms))
    await toolkit.record_metric(
        "total_secrets",
        float(len(state.discovered_secrets)),
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
