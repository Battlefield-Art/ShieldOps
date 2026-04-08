"""Data Retention Enforcer Agent — Node implementations."""

from __future__ import annotations

from typing import Any

import structlog
from pydantic import BaseModel, Field

from shieldops.utils.llm import llm_structured

from .models import DREStage
from .tools import DataRetentionEnforcerToolkit

logger = structlog.get_logger()

_toolkit: DataRetentionEnforcerToolkit | None = None


def _get_toolkit() -> DataRetentionEnforcerToolkit:
    if _toolkit is None:
        return DataRetentionEnforcerToolkit()
    return _toolkit


class _LLMRetentionInsight(BaseModel):
    """LLM-generated retention insight."""

    high_risk_assets: list[str] = Field(
        description="Assets with retention compliance risk",
    )
    policy_gaps: list[str] = Field(
        description="Gaps in retention policy coverage",
    )
    recommendation: str = Field(
        description="Overall retention posture summary",
    )


async def discover_data(
    state: dict[str, Any],
    toolkit: DataRetentionEnforcerToolkit,
) -> dict[str, Any]:
    """Discover data assets."""
    logger.info("dre.node.discover_data")

    tenant_id = state.get("tenant_id", "default")
    assets = await toolkit.discover_data(tenant_id)

    return {
        "stage": DREStage.CLASSIFY_RETENTION.value,
        "assets": assets,
        "total_assets": len(assets),
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [f"Discovered {len(assets)} data assets"],
    }


async def classify_retention(
    state: dict[str, Any],
    toolkit: DataRetentionEnforcerToolkit,
) -> dict[str, Any]:
    """Classify retention policy for each asset."""
    logger.info("dre.node.classify_retention")
    assets = state.get("assets", [])

    classifications: list[dict[str, Any]] = []
    for asset in assets:
        cls = toolkit.classify_retention(asset)
        classifications.append(cls)

    return {
        "stage": DREStage.CHECK_EXPIRY.value,
        "classifications": classifications,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [f"Classified {len(classifications)} assets by retention policy"],
    }


async def check_expiry(
    state: dict[str, Any],
    toolkit: DataRetentionEnforcerToolkit,
) -> dict[str, Any]:
    """Check expiry status of classified data."""
    logger.info("dre.node.check_expiry")
    classifications = state.get("classifications", [])

    expired = sum(1 for c in classifications if c.get("status") == "expired")
    exempt = sum(1 for c in classifications if c.get("status") == "exempt")

    llm_note = ""
    try:
        summary = "\n".join(
            f"- {c.get('asset_id')}: {c.get('policy')} / {c.get('status')}"
            for c in classifications[:20]
        )
        result = await llm_structured(
            system_prompt=(
                "You are a data retention analyst. "
                "Assess retention policy compliance and "
                "identify assets at risk of violation."
            ),
            user_prompt=(f"Data classifications:\n{summary}"),
            schema=_LLMRetentionInsight,
        )
        if isinstance(result, _LLMRetentionInsight):
            llm_note = f" LLM: {result.recommendation}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="dre",
            node="check_expiry",
        )

    note = f"Expiry check: {expired} expired, {exempt} exempt"
    return {
        "stage": DREStage.ENFORCE_DELETION.value,
        "expired_assets": expired,
        "exempt_assets": exempt,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [note + llm_note],
    }


async def enforce_deletion(
    state: dict[str, Any],
    toolkit: DataRetentionEnforcerToolkit,
) -> dict[str, Any]:
    """Enforce deletion for expired data assets."""
    logger.info("dre.node.enforce_deletion")
    classifications = state.get("classifications", [])

    deletions: list[dict[str, Any]] = []
    for cls in classifications:
        result = await toolkit.enforce_deletion(cls)
        deletions.append(result)

    deleted = sum(1 for d in deletions if d.get("deleted"))

    return {
        "stage": DREStage.VERIFY_COMPLIANCE.value,
        "deletions": deletions,
        "deleted_assets": deleted,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [f"Enforced deletion: {deleted} assets deleted"],
    }


async def verify_compliance(
    state: dict[str, Any],
    toolkit: DataRetentionEnforcerToolkit,
) -> dict[str, Any]:
    """Verify retention compliance after enforcement."""
    logger.info("dre.node.verify_compliance")
    deletions = state.get("deletions", [])

    verified = sum(1 for d in deletions if d.get("verified"))
    total_deleted = sum(1 for d in deletions if d.get("deleted"))

    return {
        "stage": DREStage.REPORT.value,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [f"Verified {verified}/{total_deleted} deletions"],
    }


async def report(
    state: dict[str, Any],
    toolkit: DataRetentionEnforcerToolkit,
) -> dict[str, Any]:
    """Generate retention enforcement report."""
    logger.info("dre.node.report")

    rpt = toolkit.generate_report(
        assets=state.get("assets", []),
        classifications=state.get(
            "classifications",
            [],
        ),
        deletions=state.get("deletions", []),
    )

    return {
        "stage": DREStage.REPORT.value,
        "report": rpt,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [f"Report: {rpt.get('deleted_assets')} deleted, {rpt.get('expired_assets')} expired"],
    }
