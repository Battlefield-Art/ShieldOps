"""NHI Registry Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    NHIStatus,
    NonHumanIdentity,
    RemediationRecommendation,
    ScanStage,
)
from .tools import NHIRegistryToolkit

logger = structlog.get_logger()

_toolkit: NHIRegistryToolkit | None = None


def set_toolkit(toolkit: NHIRegistryToolkit) -> None:
    """Set the module-level toolkit for node functions."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> NHIRegistryToolkit:
    """Get the module-level toolkit, creating a default if needed."""
    global _toolkit
    if _toolkit is None:
        _toolkit = NHIRegistryToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


async def scan_cloud_iam(state: dict[str, Any], toolkit: NHIRegistryToolkit) -> dict[str, Any]:
    """Scan AWS, GCP, and Azure for IAM non-human identities."""
    logger.info("nhi_registry.node.scan_cloud_iam")
    state = _to_dict(state)

    targets = state.get("scan_targets", [])
    identities: list[dict[str, Any]] = []

    aws_nhis = await toolkit.scan_aws_iam(
        account_id=next((t for t in targets if "aws" in t.lower()), "")
    )
    identities.extend(n.model_dump() for n in aws_nhis)

    gcp_nhis = await toolkit.scan_gcp_service_accounts(
        project_id=next((t for t in targets if "gcp" in t.lower()), "")
    )
    identities.extend(n.model_dump() for n in gcp_nhis)

    azure_nhis = await toolkit.scan_azure_app_registrations(
        tenant_id=next((t for t in targets if "azure" in t.lower()), "")
    )
    identities.extend(n.model_dump() for n in azure_nhis)

    return {
        "stage": ScanStage.SCANNING.value,
        "discovered_identities": state.get("discovered_identities", []) + identities,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Cloud IAM scan discovered {len(identities)} identities across AWS/GCP/Azure"],
    }


async def scan_kubernetes(state: dict[str, Any], toolkit: NHIRegistryToolkit) -> dict[str, Any]:
    """Scan Kubernetes clusters for service accounts."""
    logger.info("nhi_registry.node.scan_kubernetes")
    state = _to_dict(state)

    k8s_nhis = await toolkit.scan_k8s_service_accounts()
    identities = [n.model_dump() for n in k8s_nhis]

    return {
        "discovered_identities": state.get("discovered_identities", []) + identities,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Kubernetes scan found {len(identities)} service accounts"],
    }


async def scan_cicd(state: dict[str, Any], toolkit: NHIRegistryToolkit) -> dict[str, Any]:
    """Scan CI/CD platforms for tokens and service connections."""
    logger.info("nhi_registry.node.scan_cicd")
    state = _to_dict(state)

    gh_nhis = await toolkit.scan_github_tokens()
    identities = [n.model_dump() for n in gh_nhis]

    return {
        "discovered_identities": state.get("discovered_identities", []) + identities,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"CI/CD scan found {len(identities)} tokens and OAuth apps"],
    }


async def detect_shadow_ai(state: dict[str, Any], toolkit: NHIRegistryToolkit) -> dict[str, Any]:
    """Detect unregistered AI/LLM API consumers."""
    logger.info("nhi_registry.node.detect_shadow_ai")
    state = _to_dict(state)

    include = state.get("include_shadow_ai", True)
    shadow_agents: list[dict[str, Any]] = []

    if include:
        agents = await toolkit.detect_unregistered_llm_api_calls()
        shadow_agents = [a.model_dump() for a in agents]

    return {
        "shadow_ai_agents": shadow_agents,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Shadow AI detection found {len(shadow_agents)} unregistered LLM consumers"],
    }


async def classify_identities(state: dict[str, Any], toolkit: NHIRegistryToolkit) -> dict[str, Any]:
    """Classify discovered identities by type, status, and ownership."""
    logger.info("nhi_registry.node.classify_identities")
    state = _to_dict(state)

    raw_identities = state.get("discovered_identities", [])
    classified: dict[str, list[dict[str, Any]]] = {}

    for nhi_data in raw_identities:
        nhi = NonHumanIdentity(**nhi_data)
        nhi_type = nhi.nhi_type.value
        classified.setdefault(nhi_type, []).append(nhi_data)

    reasoning_note = (
        f"Classified {len(raw_identities)} identities into {len(classified)} categories"
    )

    # LLM enhancement: deeper classification analysis
    try:
        from .prompts import SYSTEM_CLASSIFY, NHIClassificationResult

        context = json.dumps(
            {
                "total_identities": len(raw_identities),
                "categories": {k: len(v) for k, v in classified.items()},
                "sample_identities": [
                    {
                        "name": n.get("name"),
                        "type": n.get("nhi_type"),
                        "provider": n.get("provider"),
                    }
                    for n in raw_identities[:15]
                ],
            },
            default=str,
        )
        llm_result = cast(
            NHIClassificationResult,
            await llm_structured(
                system_prompt=SYSTEM_CLASSIFY,
                user_prompt=f"NHI classification context:\n{context}",
                schema=NHIClassificationResult,
            ),
        )
        logger.info("llm_enhanced", agent="nhi_registry", node="classify_identities")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="nhi_registry", node="classify_identities")

    return {
        "stage": ScanStage.CLASSIFYING.value,
        "classified_identities": classified,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def assess_risk(state: dict[str, Any], toolkit: NHIRegistryToolkit) -> dict[str, Any]:
    """Score risk for each discovered identity and identify issues."""
    logger.info("nhi_registry.node.assess_risk")
    state = _to_dict(state)

    raw_identities = state.get("discovered_identities", [])
    risk_scores: dict[str, float] = {}
    orphaned: list[dict[str, Any]] = []
    over_privileged: list[dict[str, Any]] = []
    stale: list[dict[str, Any]] = []

    for nhi_data in raw_identities:
        nhi = NonHumanIdentity(**nhi_data)
        score = toolkit.calculate_risk_score(nhi)
        risk_scores[nhi.id] = score

        if nhi.status == NHIStatus.ORPHANED or not nhi.owner:
            orphaned.append(nhi_data)

        if any("*" in p for p in nhi.permissions) or len(nhi.permissions) > 10:
            over_privileged.append(nhi_data)

        import time

        idle_days = (time.time() - nhi.last_used) / 86400 if nhi.last_used > 0 else 999
        if idle_days > 90:
            stale.append(nhi_data)

    reasoning_note = (
        f"Risk assessment complete: {len(orphaned)} orphaned, "
        f"{len(over_privileged)} over-privileged, {len(stale)} stale"
    )

    # LLM enhancement: deeper risk assessment
    try:
        from .prompts import SYSTEM_ASSESS_RISK, NHIRiskAssessmentResult

        context = json.dumps(
            {
                "total_identities": len(raw_identities),
                "orphaned_count": len(orphaned),
                "over_privileged_count": len(over_privileged),
                "stale_count": len(stale),
                "high_risk_identities": [
                    {"id": k, "score": v} for k, v in risk_scores.items() if v >= 70
                ],
                "shadow_ai_count": len(state.get("shadow_ai_agents", [])),
            },
            default=str,
        )
        llm_result = cast(
            NHIRiskAssessmentResult,
            await llm_structured(
                system_prompt=SYSTEM_ASSESS_RISK,
                user_prompt=f"NHI risk context:\n{context}",
                schema=NHIRiskAssessmentResult,
            ),
        )
        logger.info("llm_enhanced", agent="nhi_registry", node="assess_risk")
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug("llm_fallback", agent="nhi_registry", node="assess_risk")

    return {
        "stage": ScanStage.ASSESSING.value,
        "risk_scores": risk_scores,
        "orphaned_identities": orphaned,
        "over_privileged_identities": over_privileged,
        "stale_credentials": stale,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def generate_recommendations(
    state: dict[str, Any], toolkit: NHIRegistryToolkit
) -> dict[str, Any]:
    """Generate remediation recommendations and policy updates."""
    logger.info("nhi_registry.node.generate_recommendations")
    state = _to_dict(state)

    recommendations: list[dict[str, Any]] = []
    policy_updates: list[dict[str, Any]] = []

    # Recommend decommissioning orphaned identities
    for nhi_data in state.get("orphaned_identities", []):
        nhi = NonHumanIdentity(**nhi_data)
        recommendations.append(
            RemediationRecommendation(
                nhi_id=nhi.id,
                action="decommission",
                priority="high",
                reason=f"Orphaned {nhi.nhi_type.value} '{nhi.name}' has no owner",
            ).model_dump()
        )

    # Recommend scoping over-privileged identities
    for nhi_data in state.get("over_privileged_identities", []):
        nhi = NonHumanIdentity(**nhi_data)
        recommendations.append(
            RemediationRecommendation(
                nhi_id=nhi.id,
                action="scope_permissions",
                priority="critical" if any("*" in p for p in nhi.permissions) else "high",
                reason=f"'{nhi.name}' has {len(nhi.permissions)} permissions including wildcards",
            ).model_dump()
        )

    # Recommend credential rotation for stale identities
    for nhi_data in state.get("stale_credentials", []):
        nhi = NonHumanIdentity(**nhi_data)
        recommendations.append(
            RemediationRecommendation(
                nhi_id=nhi.id,
                action="rotate_credentials",
                priority="medium",
                reason=f"'{nhi.name}' credentials have not been used recently",
            ).model_dump()
        )

    # Policy updates for shadow AI
    shadow_agents = state.get("shadow_ai_agents", [])
    if shadow_agents:
        policy_updates.append(
            {
                "policy": "require_ai_agent_registration",
                "description": f"Detected {len(shadow_agents)} unregistered AI consumers",
                "enforcement": "block_unregistered_llm_api_calls",
            }
        )

    return {
        "stage": ScanStage.COMPLETE.value,
        "remediation_recommendations": recommendations,
        "policy_updates": policy_updates,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Generated {len(recommendations)} recommendations and {len(policy_updates)} policies"],
    }


async def report(state: dict[str, Any], toolkit: NHIRegistryToolkit) -> dict[str, Any]:
    """Compile the final NHI registry scan report."""
    logger.info("nhi_registry.node.report")
    state = _to_dict(state)

    total = len(state.get("discovered_identities", []))
    orphaned = len(state.get("orphaned_identities", []))
    over_priv = len(state.get("over_privileged_identities", []))
    shadow = len(state.get("shadow_ai_agents", []))
    recs = len(state.get("remediation_recommendations", []))

    return {
        "stage": ScanStage.COMPLETE.value,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"NHI scan complete: {total} identities discovered, "
            f"{orphaned} orphaned, {over_priv} over-privileged, "
            f"{shadow} shadow AI agents, {recs} recommendations"
        ],
    }
