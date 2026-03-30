"""Privacy Consent Manager Agent — Node implementations."""

from __future__ import annotations

from typing import Any

import structlog
from pydantic import BaseModel, Field

from shieldops.utils.llm import llm_structured

from .models import PCMStage
from .tools import PrivacyConsentManagerToolkit

logger = structlog.get_logger()

_toolkit: PrivacyConsentManagerToolkit | None = None


def set_toolkit(
    toolkit: PrivacyConsentManagerToolkit,
) -> None:
    """Configure the module-level toolkit."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> PrivacyConsentManagerToolkit:
    if _toolkit is None:
        return PrivacyConsentManagerToolkit()
    return _toolkit


class _LLMConsentInsight(BaseModel):
    """LLM-generated consent compliance insight."""

    risk_areas: list[str] = Field(
        description="Consent compliance risk areas",
    )
    regulatory_gaps: list[str] = Field(
        description="Gaps in GDPR/CCPA compliance",
    )
    recommendation: str = Field(
        description="Overall consent posture summary",
    )


async def discover_consents(
    state: dict[str, Any],
    toolkit: PrivacyConsentManagerToolkit,
) -> dict[str, Any]:
    """Discover all consent records."""
    logger.info("pcm.node.discover_consents")

    tenant_id = state.get("tenant_id", "default")
    consents = await toolkit.discover_consents(tenant_id)

    active = sum(1 for c in consents if c.get("status") == "active")

    return {
        "stage": PCMStage.VALIDATE_RECORDS.value,
        "consents": consents,
        "total_consents": len(consents),
        "active_consents": active,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [f"Discovered {len(consents)} consents, {active} active"],
    }


async def validate_records(
    state: dict[str, Any],
    toolkit: PrivacyConsentManagerToolkit,
) -> dict[str, Any]:
    """Validate consent records."""
    logger.info("pcm.node.validate_records")
    consents = state.get("consents", [])

    validated: list[dict[str, Any]] = []
    for consent in consents:
        result = toolkit.validate_record(consent)
        validated.append(result)

    valid = sum(1 for v in validated if v.get("valid"))

    return {
        "stage": PCMStage.CHECK_EXPIRY.value,
        "consents": validated,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [f"Validated {len(validated)} records, {valid} valid"],
    }


async def check_expiry(
    state: dict[str, Any],
    toolkit: PrivacyConsentManagerToolkit,
) -> dict[str, Any]:
    """Check consent expiry status."""
    logger.info("pcm.node.check_expiry")
    consents = state.get("consents", [])

    expired = sum(1 for c in consents if c.get("status") == "expired")
    withdrawn = sum(1 for c in consents if c.get("status") == "withdrawn")

    llm_note = ""
    try:
        summary = "\n".join(
            f"- {c.get('id')}: {c.get('consent_type')} / {c.get('status')}" for c in consents[:20]
        )
        result = await llm_structured(
            system_prompt=(
                "You are a privacy consent analyst. "
                "Assess consent records for GDPR and "
                "CCPA compliance risks."
            ),
            user_prompt=f"Consent records:\n{summary}",
            schema=_LLMConsentInsight,
        )
        if isinstance(result, _LLMConsentInsight):
            llm_note = f" LLM: {result.recommendation}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="pcm",
            node="check_expiry",
        )

    note = f"Expiry check: {expired} expired, {withdrawn} withdrawn"
    return {
        "stage": PCMStage.ENFORCE_PREFERENCES.value,
        "expired_consents": expired,
        "withdrawn_consents": withdrawn,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [note + llm_note],
    }


async def enforce_preferences(
    state: dict[str, Any],
    toolkit: PrivacyConsentManagerToolkit,
) -> dict[str, Any]:
    """Enforce consent preferences downstream."""
    logger.info("pcm.node.enforce_preferences")
    consents = state.get("consents", [])

    enforcements: list[dict[str, Any]] = []
    for consent in consents:
        result = await toolkit.enforce_preference(
            consent,
        )
        enforcements.append(result)

    enforced = sum(1 for e in enforcements if e.get("enforced"))

    return {
        "stage": PCMStage.AUDIT_COMPLIANCE.value,
        "enforcements": enforcements,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [f"Enforced {enforced}/{len(enforcements)} preferences"],
    }


async def audit_compliance(
    state: dict[str, Any],
    toolkit: PrivacyConsentManagerToolkit,
) -> dict[str, Any]:
    """Audit consent compliance."""
    logger.info("pcm.node.audit_compliance")
    consents = state.get("consents", [])

    entries: list[dict[str, Any]] = []
    for consent in consents:
        entry = toolkit.audit_consent(consent)
        entries.append(entry)

    compliant = sum(1 for e in entries if e.get("compliant"))
    rate = round(compliant / len(entries) * 100, 1) if entries else 0.0

    return {
        "stage": PCMStage.REPORT.value,
        "audit_entries": entries,
        "compliance_rate": rate,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [f"Audited {len(entries)} consents, {rate}% compliant"],
    }


async def report(
    state: dict[str, Any],
    toolkit: PrivacyConsentManagerToolkit,
) -> dict[str, Any]:
    """Generate consent compliance report."""
    logger.info("pcm.node.report")

    rpt = toolkit.generate_report(
        consents=state.get("consents", []),
        enforcements=state.get("enforcements", []),
        audit_entries=state.get("audit_entries", []),
    )

    return {
        "stage": PCMStage.REPORT.value,
        "report": rpt,
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [f"Report: {rpt.get('compliance_rate')}% compliance rate"],
    }
