"""Cloud Key Manager Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    CKMStage,
    CloudKey,
    KeyRiskAssessment,
    ReasoningStep,
    RotationAudit,
)
from .tools import CloudKeyManagerToolkit

logger = structlog.get_logger()

_toolkit: CloudKeyManagerToolkit | None = None  # noqa: PLW0603


def _get_toolkit() -> CloudKeyManagerToolkit:
    """Get the module-level toolkit."""
    if _toolkit is None:
        msg = "Toolkit not set — toolkit required"
        raise RuntimeError(msg)
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Discover Keys
# ------------------------------------------------------------------


async def discover_keys(
    state: dict[str, Any],
    toolkit: CloudKeyManagerToolkit,
) -> dict[str, Any]:
    """Discover keys across cloud KMS providers."""
    logger.info("ckm.node.discover_keys")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    keys = await toolkit.discover_keys(tenant_id)
    data = [k.model_dump() for k in keys]

    note = f"Discovered {len(keys)} keys across cloud providers"

    return {
        "stage": CKMStage.AUDIT_ROTATION.value,
        "keys": data,
        "total_keys_discovered": len(keys),
        "current_step": "discover_keys",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="discover_keys",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Audit Rotation
# ------------------------------------------------------------------


async def audit_rotation(
    state: dict[str, Any],
    toolkit: CloudKeyManagerToolkit,
) -> dict[str, Any]:
    """Audit key rotation compliance."""
    logger.info("ckm.node.audit_rotation")
    state = _to_dict(state)

    keys = [CloudKey(**k) for k in state.get("keys", [])]
    audits = await toolkit.audit_rotation(keys)
    data = [a.model_dump() for a in audits]

    non_compliant = sum(1 for a in audits if not a.compliant)
    note = f"Audited {len(audits)} keys, {non_compliant} non-compliant"

    try:
        from .prompts import SYSTEM_ANALYZE, RotationInsight

        ctx = json.dumps(
            {
                "audits": [
                    {
                        "key_id": a.key_id,
                        "days": a.days_since_rotation,
                        "compliant": a.compliant,
                        "provider": a.provider.value,
                    }
                    for a in audits[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            RotationInsight,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"Key rotation audits:\n{ctx}",
                schema=RotationInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="ckm",
            node="audit_rotation",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="ckm",
            node="audit_rotation",
        )

    return {
        "stage": CKMStage.CHECK_USAGE.value,
        "rotation_audits": data,
        "current_step": "audit_rotation",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="audit_rotation",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Check Usage
# ------------------------------------------------------------------


async def check_usage(
    state: dict[str, Any],
    toolkit: CloudKeyManagerToolkit,
) -> dict[str, Any]:
    """Analyze key usage patterns."""
    logger.info("ckm.node.check_usage")
    state = _to_dict(state)

    keys = [CloudKey(**k) for k in state.get("keys", [])]
    usages = await toolkit.check_usage(keys)
    data = [u.model_dump() for u in usages]

    unused = sum(1 for u in usages if u.unused_days > 30)
    note = f"Analyzed usage for {len(usages)} keys, {unused} potentially unused"

    return {
        "stage": CKMStage.ASSESS_RISK.value,
        "usages": data,
        "current_step": "check_usage",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="check_usage",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Assess Risk
# ------------------------------------------------------------------


async def assess_risk(
    state: dict[str, Any],
    toolkit: CloudKeyManagerToolkit,
) -> dict[str, Any]:
    """Assess risk for each key."""
    logger.info("ckm.node.assess_risk")
    state = _to_dict(state)

    keys = [CloudKey(**k) for k in state.get("keys", [])]
    audits = [RotationAudit(**a) for a in state.get("rotation_audits", [])]
    assessments = await toolkit.assess_risk(keys, audits)
    data = [a.model_dump() for a in assessments]

    at_risk = sum(1 for a in assessments if a.risk.value in ("critical", "high"))
    note = f"Assessed {len(assessments)} keys, {at_risk} at risk"

    return {
        "stage": CKMStage.ENFORCE_POLICY.value,
        "risk_assessments": data,
        "keys_at_risk": at_risk,
        "current_step": "assess_risk",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="assess_risk",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Enforce Policy
# ------------------------------------------------------------------


async def enforce_policy(
    state: dict[str, Any],
    toolkit: CloudKeyManagerToolkit,
) -> dict[str, Any]:
    """Enforce key management policies."""
    logger.info("ckm.node.enforce_policy")
    state = _to_dict(state)

    assessments = [KeyRiskAssessment(**a) for a in state.get("risk_assessments", [])]
    enforcements = await toolkit.enforce_policy(assessments)
    data = [e.model_dump() for e in enforcements]

    enforced = sum(1 for e in enforcements if e.status == "enforced")
    note = f"Enforced {enforced}/{len(enforcements)} key policies"

    return {
        "stage": CKMStage.REPORT.value,
        "enforcements": data,
        "current_step": "enforce_policy",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="enforce_policy",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: CloudKeyManagerToolkit,
) -> dict[str, Any]:
    """Compile the final cloud key management report."""
    logger.info("ckm.node.report")
    state = _to_dict(state)

    total_keys = state.get("total_keys_discovered", 0)
    at_risk = state.get("keys_at_risk", 0)
    audit_count = len(state.get("rotation_audits", []))
    enforce_count = len(state.get("enforcements", []))

    lines = [
        "# Cloud Key Management Report",
        "",
        f"**Keys discovered:** {total_keys}",
        f"**Keys at risk:** {at_risk}",
        f"**Rotation audits:** {audit_count}",
        f"**Policies enforced:** {enforce_count}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "total_keys": total_keys,
                "at_risk": at_risk,
                "audits": audit_count,
                "enforcements": enforce_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Key management report:\n{ctx}",
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="ckm",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="ckm",
            node="report",
        )

    return {
        "stage": CKMStage.REPORT.value,
        "report": report_text,
        "current_step": "report",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="report",
                detail="Final report compiled",
                confidence=0.95,
            ).model_dump()
        ],
    }
