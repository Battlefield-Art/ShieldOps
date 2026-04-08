"""Credential Lifecycle Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    CredentialRecord,
    CredentialType,
    LifecycleStage,
)
from .tools import CredentialLifecycleToolkit

logger = structlog.get_logger()

# Module-level toolkit reference for node functions
_toolkit: CredentialLifecycleToolkit | None = None


def _get_toolkit() -> CredentialLifecycleToolkit:
    """Get the module-level toolkit, creating a default if needed."""
    global _toolkit
    if _toolkit is None:
        _toolkit = CredentialLifecycleToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def discover_credentials(
    state: dict[str, Any], toolkit: CredentialLifecycleToolkit
) -> dict[str, Any]:
    """Discover credentials across cloud IAM, vault, K8s secrets, env vars."""
    logger.info("credential_lifecycle.node.discover_credentials")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "unknown")
    scan_scope = state.get("scan_scope", ["cloud_iam", "vault", "k8s", "env"])

    credentials = await toolkit.discover_credentials(tenant_id, scan_scope)
    credentials_data = [c.model_dump() for c in credentials]

    reasoning_note = f"Discovered {len(credentials)} credentials across {len(scan_scope)} scopes"

    return {
        "stage": LifecycleStage.ASSESS_POSTURE.value,
        "discovered_credentials": credentials_data,
        "current_step": "discover_credentials",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def assess_posture(
    state: dict[str, Any], toolkit: CredentialLifecycleToolkit
) -> dict[str, Any]:
    """Assess credential posture — age, usage, scope, rotation compliance."""
    logger.info("credential_lifecycle.node.assess_posture")
    state = _to_dict(state)

    creds_data = state.get("discovered_credentials", [])
    credentials = [CredentialRecord(**c) for c in creds_data]

    assessments = await toolkit.assess_credential_posture(credentials)
    assessments_data = [a.model_dump() for a in assessments]

    stale_count = sum(1 for a in assessments if a.last_rotation_days > 90)
    overprivileged_count = sum(1 for a in assessments if a.overprivileged)
    critical_count = sum(1 for a in assessments if a.rating == "critical")

    reasoning_note = (
        f"Assessed {len(assessments)} credentials: "
        f"{critical_count} critical, {stale_count} stale, "
        f"{overprivileged_count} overprivileged"
    )

    # LLM enhancement: deeper posture analysis
    try:
        from .prompts import SYSTEM_POSTURE_ANALYSIS, PostureAnalysisOutput

        context_json = json.dumps(
            {
                "tenant_id": state.get("tenant_id", "unknown"),
                "total_credentials": len(assessments),
                "critical_count": critical_count,
                "stale_count": stale_count,
                "overprivileged_count": overprivileged_count,
                "assessments_summary": [
                    {
                        "credential_id": a.credential_id,
                        "rating": a.rating,
                        "issues_count": len(a.issues),
                        "overprivileged": a.overprivileged,
                        "last_rotation_days": a.last_rotation_days,
                    }
                    for a in assessments[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            PostureAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_POSTURE_ANALYSIS,
                user_prompt=f"Credential posture analysis context:\n{context_json}",
                schema=PostureAnalysisOutput,
            ),
        )
        logger.info("llm_enhanced", agent="credential_lifecycle", node="assess_posture")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="credential_lifecycle", node="assess_posture")

    return {
        "stage": LifecycleStage.ISSUE_JIT.value,
        "posture_assessments": assessments_data,
        "current_step": "assess_posture",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def issue_jit_credentials(
    state: dict[str, Any], toolkit: CredentialLifecycleToolkit
) -> dict[str, Any]:
    """Issue JIT credentials for overprivileged or high-risk credentials."""
    logger.info("credential_lifecycle.node.issue_jit_credentials")
    state = _to_dict(state)

    assessments_data = state.get("posture_assessments", [])
    creds_data = state.get("discovered_credentials", [])

    # Build lookup
    cred_by_id: dict[str, dict[str, Any]] = {c["id"]: c for c in creds_data}

    # Issue JIT replacements for critical/poor posture credentials
    jit_issued: list[dict[str, Any]] = []
    for assessment in assessments_data:
        rating = assessment.get("rating", "good")
        if rating not in ("critical", "poor"):
            continue

        cred_id = assessment.get("credential_id", "")
        cred = cred_by_id.get(cred_id, {})
        cred_type_str = cred.get("credential_type", "api_key")

        try:
            cred_type = CredentialType(cred_type_str)
        except ValueError:
            cred_type = CredentialType.API_KEY

        # Issue minimal-scope JIT credential
        jit = await toolkit.issue_jit_credential(
            credential_type=cred_type,
            scope=["read"],  # Least privilege
            ttl_seconds=3600,
            requester=cred.get("owner", "unknown"),
        )
        jit_issued.append(jit.model_dump())

    reasoning_note = f"Issued {len(jit_issued)} JIT credentials for high-risk credentials"

    # LLM enhancement: JIT recommendations
    try:
        from .prompts import SYSTEM_JIT_RECOMMENDATION, JITRecommendationOutput

        context_json = json.dumps(
            {
                "total_assessments": len(assessments_data),
                "jit_issued": len(jit_issued),
                "critical_assessments": [
                    a for a in assessments_data if a.get("rating") in ("critical", "poor")
                ][:10],
            },
            default=str,
        )
        llm_result = cast(
            JITRecommendationOutput,
            await llm_structured(
                system_prompt=SYSTEM_JIT_RECOMMENDATION,
                user_prompt=f"JIT credential recommendation context:\n{context_json}",
                schema=JITRecommendationOutput,
            ),
        )
        logger.info("llm_enhanced", agent="credential_lifecycle", node="issue_jit_credentials")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="credential_lifecycle", node="issue_jit_credentials")

    return {
        "stage": LifecycleStage.ENFORCE_ROTATION.value,
        "jit_credentials_issued": jit_issued,
        "current_step": "issue_jit_credentials",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def enforce_rotation(
    state: dict[str, Any], toolkit: CredentialLifecycleToolkit
) -> dict[str, Any]:
    """Rotate credentials that exceed rotation policy thresholds."""
    logger.info("credential_lifecycle.node.enforce_rotation")
    state = _to_dict(state)

    creds_data = state.get("discovered_credentials", [])
    assessments_data = state.get("posture_assessments", [])

    # Find credentials needing rotation (stale or overdue)
    stale_cred_ids = {
        a["credential_id"]
        for a in assessments_data
        if a.get("rating") in ("critical", "poor", "fair") and a.get("last_rotation_days", 0) > 30
    }
    stale_creds = [CredentialRecord(**c) for c in creds_data if c.get("id") in stale_cred_ids]

    results = await toolkit.enforce_rotation(stale_creds)
    results_data = [r.model_dump() for r in results]

    success_count = sum(1 for r in results if r.success)
    failed_count = len(results) - success_count

    reasoning_note = (
        f"Rotated {success_count}/{len(results)} credentials "
        f"({failed_count} require manual rotation)"
    )

    # LLM enhancement: rotation planning
    try:
        from .prompts import SYSTEM_ROTATION_PLANNING, RotationPlanOutput

        context_json = json.dumps(
            {
                "total_rotated": len(results),
                "success_count": success_count,
                "failed_count": failed_count,
                "rotation_summary": [
                    {
                        "credential_id": r.credential_id,
                        "success": r.success,
                        "error": r.error_message,
                    }
                    for r in results[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            RotationPlanOutput,
            await llm_structured(
                system_prompt=SYSTEM_ROTATION_PLANNING,
                user_prompt=f"Rotation planning context:\n{context_json}",
                schema=RotationPlanOutput,
            ),
        )
        logger.info("llm_enhanced", agent="credential_lifecycle", node="enforce_rotation")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="credential_lifecycle", node="enforce_rotation")

    return {
        "stage": LifecycleStage.REVOKE_STALE.value,
        "rotation_results": results_data,
        "current_step": "enforce_rotation",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def revoke_stale(
    state: dict[str, Any], toolkit: CredentialLifecycleToolkit
) -> dict[str, Any]:
    """Revoke unused or compromised credentials."""
    logger.info("credential_lifecycle.node.revoke_stale")
    state = _to_dict(state)

    creds_data = state.get("discovered_credentials", [])

    # Revoke credentials that are stale and have high risk
    revoke_targets = [
        CredentialRecord(**c)
        for c in creds_data
        if c.get("is_stale") and c.get("risk_score", 0) >= 0.7
    ]

    results = await toolkit.revoke_stale_credentials(revoke_targets)
    results_data = [r.model_dump() for r in results]

    reasoning_note = f"Revoked {len(results)} stale/high-risk credentials"

    # LLM enhancement: revocation analysis
    try:
        from .prompts import SYSTEM_REVOCATION_ANALYSIS, RevocationOutput

        context_json = json.dumps(
            {
                "total_revoked": len(results),
                "revocation_summary": [
                    {
                        "credential_id": r.credential_id,
                        "reason": r.reason,
                        "success": r.success,
                    }
                    for r in results[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            RevocationOutput,
            await llm_structured(
                system_prompt=SYSTEM_REVOCATION_ANALYSIS,
                user_prompt=f"Revocation analysis context:\n{context_json}",
                schema=RevocationOutput,
            ),
        )
        logger.info("llm_enhanced", agent="credential_lifecycle", node="revoke_stale")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="credential_lifecycle", node="revoke_stale")

    return {
        "stage": LifecycleStage.REPORT.value,
        "revocation_results": results_data,
        "current_step": "revoke_stale",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def generate_report(
    state: dict[str, Any], toolkit: CredentialLifecycleToolkit
) -> dict[str, Any]:
    """Summarize all credential lifecycle actions into final report."""
    logger.info("credential_lifecycle.node.generate_report")
    state = _to_dict(state)

    session_start = state.get("session_start", 0.0)
    duration = (time.time() - session_start) * 1000 if session_start > 0 else 0.0

    total_discovered = len(state.get("discovered_credentials", []))
    total_assessments = len(state.get("posture_assessments", []))
    total_jit = len(state.get("jit_credentials_issued", []))
    total_rotated = len(state.get("rotation_results", []))
    total_revoked = len(state.get("revocation_results", []))

    return {
        "stage": LifecycleStage.REPORT.value,
        "session_duration_ms": round(duration, 2),
        "current_step": "report",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Credential Lifecycle complete: {total_discovered} discovered, "
            f"{total_assessments} assessed, {total_jit} JIT issued, "
            f"{total_rotated} rotated, {total_revoked} revoked"
        ],
    }
