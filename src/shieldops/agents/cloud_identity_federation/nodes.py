"""Cloud Identity Federation Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    FederatedIdentity,
    FederationMapping,
    FederationStage,
    SsoMisconfiguration,
)
from .tools import CloudIdentityFederationToolkit

logger = structlog.get_logger()

_toolkit: CloudIdentityFederationToolkit | None = None


def set_toolkit(
    toolkit: CloudIdentityFederationToolkit,
) -> None:
    """Set the module-level toolkit for node functions."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> CloudIdentityFederationToolkit:
    global _toolkit
    if _toolkit is None:
        _toolkit = CloudIdentityFederationToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def discover_identities(
    state: dict[str, Any],
    toolkit: CloudIdentityFederationToolkit,
) -> dict[str, Any]:
    """Discover federated identities."""
    logger.info("cif.node.discover")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "")
    idps = state.get("identity_providers", ["okta"])

    identities = await toolkit.discover_identities(tenant_id, idps)
    identities_data = [i.model_dump() for i in identities]

    return {
        "stage": FederationStage.MAP_FEDERATIONS.value,
        "federated_identities": identities_data,
        "current_step": "discover_identities",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Discovered {len(identities)} federated identities from {', '.join(idps)}"],
    }


async def map_federations(
    state: dict[str, Any],
    toolkit: CloudIdentityFederationToolkit,
) -> dict[str, Any]:
    """Map federation trust relationships."""
    logger.info("cif.node.map_fed")
    state = _to_dict(state)

    raw_ids = state.get("federated_identities", [])
    identities = [FederatedIdentity(**i) for i in raw_ids]

    mappings = await toolkit.map_federations(identities)
    mappings_data = [m.model_dump() for m in mappings]

    return {
        "stage": FederationStage.DETECT_MISCONFIGS.value,
        "federation_mappings": mappings_data,
        "current_step": "map_federations",
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Mapped {len(mappings)} federation trust relationships"],
    }


async def detect_misconfigs(
    state: dict[str, Any],
    toolkit: CloudIdentityFederationToolkit,
) -> dict[str, Any]:
    """Detect SSO misconfigurations."""
    logger.info("cif.node.misconfigs")
    state = _to_dict(state)

    raw_mappings = state.get("federation_mappings", [])
    mappings = [FederationMapping(**m) for m in raw_mappings]
    raw_ids = state.get("federated_identities", [])
    identities = [FederatedIdentity(**i) for i in raw_ids]

    misconfigs = await toolkit.detect_sso_misconfigs(mappings, identities)
    misconfigs_data = [m.model_dump() for m in misconfigs]

    critical = sum(1 for m in misconfigs if m.severity == "critical")
    reasoning_note = f"Found {len(misconfigs)} SSO misconfigurations, {critical} critical"

    try:
        from .prompts import (
            SYSTEM_FEDERATION_ANALYSIS,
            FederationAnalysisOutput,
        )

        context = json.dumps(
            {
                "misconfigs": len(misconfigs),
                "critical": critical,
                "types": list({m.misconfig_type for m in misconfigs}),
            },
            default=str,
        )
        llm_result = cast(
            FederationAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_FEDERATION_ANALYSIS,
                user_prompt=(f"Federation context:\n{context}"),
                schema=FederationAnalysisOutput,
            ),
        )
        logger.info("llm_enhanced", agent="cif", node="misconfigs")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="cif", node="misconfigs")

    return {
        "stage": FederationStage.ANALYZE_TRUST.value,
        "sso_misconfigs": misconfigs_data,
        "current_step": "detect_misconfigs",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def analyze_trust(
    state: dict[str, Any],
    toolkit: CloudIdentityFederationToolkit,
) -> dict[str, Any]:
    """Analyze federation trust chains."""
    logger.info("cif.node.trust")
    state = _to_dict(state)

    raw_mappings = state.get("federation_mappings", [])
    mappings = [FederationMapping(**m) for m in raw_mappings]
    raw_misconfigs = state.get("sso_misconfigs", [])
    misconfigs = [SsoMisconfiguration(**m) for m in raw_misconfigs]

    analyses = await toolkit.analyze_trust_chains(mappings, misconfigs)
    analyses_data = [a.model_dump() for a in analyses]

    reasoning_note = f"Analyzed {len(analyses)} trust chains"

    try:
        from .prompts import (
            SYSTEM_TRUST_CHAIN,
            TrustChainOutput,
        )

        context = json.dumps(
            {
                "chains": len(analyses),
                "avg_score": round(
                    sum(a.trust_score for a in analyses) / max(1, len(analyses)),
                    1,
                ),
            },
            default=str,
        )
        llm_result = cast(
            TrustChainOutput,
            await llm_structured(
                system_prompt=SYSTEM_TRUST_CHAIN,
                user_prompt=f"Trust context:\n{context}",
                schema=TrustChainOutput,
            ),
        )
        logger.info("llm_enhanced", agent="cif", node="trust")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="cif", node="trust")

    return {
        "stage": FederationStage.ASSESS_RISK.value,
        "trust_analyses": analyses_data,
        "current_step": "analyze_trust",
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def assess_risk(
    state: dict[str, Any],
    toolkit: CloudIdentityFederationToolkit,
) -> dict[str, Any]:
    """Assess overall federation risk."""
    logger.info("cif.node.risk")
    state = _to_dict(state)

    raw_ids = state.get("federated_identities", [])
    raw_mappings = state.get("federation_mappings", [])
    raw_misconfigs = state.get("sso_misconfigs", [])
    raw_trust = state.get("trust_analyses", [])

    risk_scores = [m.get("risk_score", 0.0) for m in raw_misconfigs]
    risk_score = round(max(risk_scores) if risk_scores else 0.0, 1)

    elapsed = round(
        (time.time() - state.get("session_start", time.time())) * 1000,
        1,
    )

    stats = {
        "identities_discovered": len(raw_ids),
        "federation_mappings": len(raw_mappings),
        "sso_misconfigs": len(raw_misconfigs),
        "trust_chains_analyzed": len(raw_trust),
        "risk_score": risk_score,
    }

    report_summary = (
        f"Federation risk: {risk_score}/100."
        f" {len(raw_ids)} identities,"
        f" {len(raw_misconfigs)} misconfigs,"
        f" {len(raw_trust)} trust chains."
    )

    try:
        from .prompts import (
            SYSTEM_IDENTITY_RISK,
            IdentityRiskOutput,
        )

        context = json.dumps(stats, default=str)
        llm_result = cast(
            IdentityRiskOutput,
            await llm_structured(
                system_prompt=SYSTEM_IDENTITY_RISK,
                user_prompt=f"Risk context:\n{context}",
                schema=IdentityRiskOutput,
            ),
        )
        logger.info("llm_enhanced", agent="cif", node="risk")
        report_summary = llm_result.summary
    except Exception:
        logger.debug("llm_fallback", agent="cif", node="risk")

    return {
        "stage": FederationStage.REPORT.value,
        "risk_score": risk_score,
        "stats": stats,
        "session_duration_ms": elapsed,
        "current_step": "assess_risk",
        "reasoning_chain": state.get("reasoning_chain", []) + [report_summary],
    }
