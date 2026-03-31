"""API Token Rotator Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    AgeAudit,
    ATRStage,
    ReasoningStep,
    RiskAssessment,
    TokenRecord,
)
from .tools import APITokenRotatorToolkit

logger = structlog.get_logger()

_toolkit: APITokenRotatorToolkit | None = None  # noqa: PLW0603


def set_toolkit(tk: APITokenRotatorToolkit) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = tk


def _get_toolkit() -> APITokenRotatorToolkit:
    if _toolkit is None:
        msg = "Toolkit not initialized"
        raise RuntimeError(msg)
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Discover Tokens
# ------------------------------------------------------------------


async def discover_tokens(
    state: dict[str, Any],
    toolkit: APITokenRotatorToolkit,
) -> dict[str, Any]:
    """Discover API tokens across services."""
    logger.info("atr.node.discover_tokens")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    tokens = await toolkit.discover_tokens(tenant_id)
    data = [t.model_dump() for t in tokens]

    note = f"Discovered {len(tokens)} API tokens"

    return {
        "stage": ATRStage.AUDIT_AGE.value,
        "tokens": data,
        "total_tokens_discovered": len(tokens),
        "current_step": "discover_tokens",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="discover_tokens",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Audit Age
# ------------------------------------------------------------------


async def audit_age(
    state: dict[str, Any],
    toolkit: APITokenRotatorToolkit,
) -> dict[str, Any]:
    """Audit token ages against rotation policy."""
    logger.info("atr.node.audit_age")
    state = _to_dict(state)

    tokens = [TokenRecord(**t) for t in state.get("tokens", [])]
    audits = await toolkit.audit_age(tokens)
    data = [a.model_dump() for a in audits]

    stale = sum(1 for a in audits if a.is_stale)
    note = f"Audited {len(audits)} tokens, {stale} stale"

    try:
        from .prompts import SYSTEM_ANALYZE, AuditInsight

        ctx = json.dumps(
            {
                "audits": [
                    {
                        "token_id": a.token_id,
                        "age_days": a.age_days,
                        "max_age": a.max_age_policy,
                        "stale": a.is_stale,
                    }
                    for a in audits[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            AuditInsight,
            await llm_structured(
                system_prompt=SYSTEM_ANALYZE,
                user_prompt=f"Token age audits:\n{ctx}",
                schema=AuditInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="atr",
            node="audit_age",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="atr",
            node="audit_age",
        )

    return {
        "stage": ATRStage.ASSESS_RISK.value,
        "age_audits": data,
        "current_step": "audit_age",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="audit_age",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Assess Risk
# ------------------------------------------------------------------


async def assess_risk(
    state: dict[str, Any],
    toolkit: APITokenRotatorToolkit,
) -> dict[str, Any]:
    """Assess risk for each token."""
    logger.info("atr.node.assess_risk")
    state = _to_dict(state)

    tokens = [TokenRecord(**t) for t in state.get("tokens", [])]
    audits = [AgeAudit(**a) for a in state.get("age_audits", [])]
    assessments = await toolkit.assess_risk(tokens, audits)
    data = [a.model_dump() for a in assessments]

    critical = sum(1 for a in assessments if a.risk.value == "critical")
    high = sum(1 for a in assessments if a.risk.value == "high")
    note = f"Assessed {len(assessments)} tokens, {critical} critical, {high} high"

    return {
        "stage": ATRStage.GENERATE_NEW.value,
        "risk_assessments": data,
        "current_step": "assess_risk",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="assess_risk",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Generate New / Rotate
# ------------------------------------------------------------------


async def rotate_tokens(
    state: dict[str, Any],
    toolkit: APITokenRotatorToolkit,
) -> dict[str, Any]:
    """Rotate tokens that need rotation."""
    logger.info("atr.node.rotate")
    state = _to_dict(state)

    tokens = [TokenRecord(**t) for t in state.get("tokens", [])]
    assessments = [RiskAssessment(**a) for a in state.get("risk_assessments", [])]
    rotations = await toolkit.rotate_token(tokens, assessments)
    data = [r.model_dump() for r in rotations]

    rotated = sum(1 for r in rotations if r.new_token_generated)
    note = f"Rotated {rotated}/{len(rotations)} tokens"

    return {
        "stage": ATRStage.REPORT.value,
        "rotations": data,
        "tokens_rotated": rotated,
        "current_step": "rotate",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="rotate",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Report
# ------------------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: APITokenRotatorToolkit,
) -> dict[str, Any]:
    """Compile the final token rotation report."""
    logger.info("atr.node.report")
    state = _to_dict(state)

    total_tokens = state.get("total_tokens_discovered", 0)
    rotated = state.get("tokens_rotated", 0)
    risk_count = len(state.get("risk_assessments", []))

    lines = [
        "# API Token Rotation Report",
        "",
        f"**Tokens discovered:** {total_tokens}",
        f"**Tokens assessed:** {risk_count}",
        f"**Tokens rotated:** {rotated}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import SYSTEM_REPORT, ReportInsight

        ctx = json.dumps(
            {
                "total_tokens": total_tokens,
                "rotated": rotated,
                "assessments": risk_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Token rotation report:\n{ctx}",
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="atr",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="atr",
            node="report",
        )

    return {
        "stage": ATRStage.REPORT.value,
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
