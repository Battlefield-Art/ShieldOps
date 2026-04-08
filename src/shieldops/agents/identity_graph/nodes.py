"""Node implementations for the Identity Graph Agent LangGraph workflow."""

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.identity_graph.models import (
    IdentityGraphState,
    IdentityNode,
    ReasoningStep,
    RiskAssessment,
    TrustRelationship,
)
from shieldops.agents.identity_graph.prompts import (
    SYSTEM_IDENTITY_RISK_ASSESSMENT,
    SYSTEM_LATERAL_MOVEMENT_ANALYSIS,
    SYSTEM_REMEDIATION_GENERATION,
    IdentityRiskResult,
    LateralMovementResult,
    RemediationPlanResult,
)
from shieldops.agents.identity_graph.tools import IdentityGraphToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: IdentityGraphToolkit | None = None


def _get_toolkit() -> IdentityGraphToolkit:
    if _toolkit is None:
        return IdentityGraphToolkit()
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


async def discover_identities(state: IdentityGraphState) -> dict[str, Any]:
    """Discover all identities in the target org/tenant.

    Performs multi-source discovery:
    1. Directory scan (Azure AD, Okta, etc.)
    2. AWS IAM enumeration (users, roles, access keys)
    3. CrowdStrike host identity correlation
    4. NHI (non-human identity) detection and cataloging
    5. Service account and AI agent permission mapping
    """
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "identity_graph.discovering_identities",
        target=state.scan_target,
        types=state.identity_types,
    )

    # OPA policy check for scan permission
    policy_result = await toolkit.check_policy(
        action="scan",
        target_identities=[state.scan_target],
        environment=state.scope.get("environment", "production"),
    )
    if not policy_result.get("allowed", True):
        logger.warning(
            "identity_graph.scan_denied",
            reason=policy_result.get("reason", ""),
        )

    # Phase 1: Directory scan (existing providers)
    raw_identities = await toolkit.scan_directory(state.scan_target, state.identity_types)
    service_accounts = await toolkit.map_service_accounts(state.scan_target)
    ai_agents = await toolkit.trace_ai_agent_permissions(state.scan_target)

    # Phase 2: AWS IAM enumeration
    iam_users = await toolkit.enumerate_iam_users()
    iam_roles = await toolkit.enumerate_iam_roles()
    stale_credentials = await toolkit.identify_stale_credentials(iam_users)

    # Phase 3: CrowdStrike identity correlation
    cs_hosts = await toolkit.fetch_crowdstrike_hosts()
    correlations = await toolkit.correlate_crowdstrike_aws_identities(iam_users, cs_hosts)

    # Phase 4: NHI discovery
    nhis = await toolkit.discover_nhis(iam_users, iam_roles)

    # Build identity nodes from all sources
    identities: list[IdentityNode] = []

    # From directory scan
    for raw in raw_identities:
        identities.append(
            IdentityNode(
                identity_id=raw.get("identity_id", ""),
                identity_name=raw.get("identity_name", ""),
                identity_type=raw.get("identity_type", "human"),
                provider=raw.get("provider", ""),
                permissions=raw.get("permissions", []),
                groups=raw.get("groups", []),
                mfa_enabled=raw.get("mfa_enabled", False),
            )
        )

    # From service accounts
    for sa in service_accounts:
        identities.append(
            IdentityNode(
                identity_id=sa.get("account_name", ""),
                identity_name=sa.get("account_name", ""),
                identity_type="service_account",
                provider=sa.get("type", ""),
                permissions=sa.get("permissions", []),
            )
        )

    # From AI agents
    for agent in ai_agents:
        identities.append(
            IdentityNode(
                identity_id=agent.get("agent_id", ""),
                identity_name=agent.get("agent_id", ""),
                identity_type="ai_agent",
                provider="shieldops",
                permissions=agent.get("permissions", []),
            )
        )

    # From AWS IAM users (deduplicate by identity_id)
    seen_ids = {i.identity_id for i in identities}
    for user in iam_users:
        uid = user.get("user_name", "")
        if uid and uid not in seen_ids:
            policies = user.get("attached_policies", [])
            identities.append(
                IdentityNode(
                    identity_id=uid,
                    identity_name=uid,
                    identity_type=(
                        "service_account" if "/service/" in user.get("path", "") else "human"
                    ),
                    provider="aws_iam",
                    permissions=[p.get("policy_name", "") for p in policies],
                    groups=user.get("groups", []),
                    mfa_enabled=False,
                    metadata={
                        "arn": user.get("arn", ""),
                        "access_key_count": len(user.get("access_keys", [])),
                    },
                )
            )
            seen_ids.add(uid)

    # From AWS IAM roles
    for role in iam_roles:
        rid = role.get("role_name", "")
        if rid and rid not in seen_ids:
            policies = role.get("attached_policies", [])
            identities.append(
                IdentityNode(
                    identity_id=rid,
                    identity_name=rid,
                    identity_type="service_account",
                    provider="aws_iam",
                    permissions=[p.get("policy_name", "") for p in policies],
                    metadata={
                        "arn": role.get("arn", ""),
                        "trust_policy": role.get("trust_policy", {}),
                    },
                )
            )
            seen_ids.add(rid)

    # Store enrichment data in scope for downstream nodes
    enrichment = {
        "iam_users": iam_users,
        "iam_roles": iam_roles,
        "stale_credentials": stale_credentials,
        "cs_hosts": cs_hosts,
        "correlations": correlations,
        "nhis": nhis,
    }

    step = ReasoningStep(
        step_number=1,
        action="discover_identities",
        input_summary=f"Scanning {state.scan_target} for {state.identity_types}",
        output_summary=(
            f"Discovered {len(identities)} identities "
            f"({len(iam_users)} IAM users, {len(iam_roles)} roles, "
            f"{len(nhis)} NHIs, {len(correlations)} CS correlations)"
        ),
        duration_ms=_elapsed_ms(start),
        tool_used="directory_scan+iam+crowdstrike+nhi",
    )

    return {
        "identities_discovered": identities,
        "credential_risks": [
            {
                "identity_id": s["user_name"],
                "risk": "stale_credential",
                "idle_days": s.get("idle_days"),
                "age_days": s.get("age_days"),
            }
            for s in stale_credentials
        ],
        "reasoning_chain": [step],
        "current_step": "discover_identities",
        "session_start": start,
        "scope": {**state.scope, "_enrichment": enrichment},
    }


async def map_relationships(state: IdentityGraphState) -> dict[str, Any]:
    """Map trust relationships between discovered identities."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "identity_graph.mapping_relationships",
        identity_count=len(state.identities_discovered),
    )

    oauth_grants = await toolkit.enumerate_oauth_grants(state.scan_target)

    relationships: list[TrustRelationship] = []
    # Map OAuth delegations
    for grant in oauth_grants:
        relationships.append(
            TrustRelationship(
                source_id=grant.get("principal_id", ""),
                target_id=grant.get("app_name", ""),
                relationship_type="oauth_delegation",
                scope=", ".join(grant.get("scopes", [])),
                trust_level=0.6,
            )
        )

    # Map group-based relationships
    group_members: dict[str, list[str]] = {}
    for identity in state.identities_discovered:
        for group in identity.groups:
            group_members.setdefault(group, []).append(identity.identity_id)

    for group, members in group_members.items():
        for i, m1 in enumerate(members):
            for m2 in members[i + 1 :]:
                relationships.append(
                    TrustRelationship(
                        source_id=m1,
                        target_id=m2,
                        relationship_type="group_membership",
                        scope=group,
                        trust_level=0.5,
                    )
                )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="map_relationships",
        input_summary=f"Mapping relationships for {len(state.identities_discovered)} identities",
        output_summary=f"Mapped {len(relationships)} trust relationships",
        duration_ms=_elapsed_ms(start),
        tool_used="oauth_grants + group_analysis",
    )

    return {
        "relationships_mapped": relationships,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "map_relationships",
    }


async def analyze_trust_chains(state: IdentityGraphState) -> dict[str, Any]:
    """Analyze trust chains for transitive risks."""
    start = datetime.now(UTC)

    logger.info(
        "identity_graph.analyzing_trust_chains",
        relationship_count=len(state.relationships_mapped),
    )

    # Build adjacency and trace chains
    adjacency: dict[str, list[str]] = {}
    for rel in state.relationships_mapped:
        adjacency.setdefault(rel.source_id, []).append(rel.target_id)

    chains: list[list[str]] = []
    for source in adjacency:
        visited: set[str] = set()
        stack: list[tuple[str, list[str]]] = [(source, [source])]
        while stack:
            current, path = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            if len(path) > 1:
                chains.append(path[:])
            for neighbor in adjacency.get(current, []):
                if neighbor not in visited:
                    stack.append((neighbor, [*path, neighbor]))

    # Filter to chains of length >= 2
    significant_chains = [c for c in chains if len(c) >= 3]

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="analyze_trust_chains",
        input_summary=f"Analyzing {len(state.relationships_mapped)} relationships",
        output_summary=f"Found {len(significant_chains)} trust chains of depth >= 2",
        duration_ms=_elapsed_ms(start),
        tool_used="graph_traversal",
    )

    return {
        "trust_chains": significant_chains[:50],
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_trust_chains",
    }


async def assess_risks(state: IdentityGraphState) -> dict[str, Any]:
    """Assess risks using LLM analysis of the identity graph.

    Enhanced with:
    - NHI-aware risk assessment via toolkit.assess_identity_risk_llm()
    - Stale credential detection from IAM enumeration
    - CrowdStrike correlation enrichment
    - Heuristic fallback when LLM is unavailable
    """
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info("identity_graph.assessing_risks", identity_count=len(state.identities_discovered))

    # Extract enrichment data from scope (set by discover_identities)
    enrichment = state.scope.get("_enrichment", {})
    nhis = enrichment.get("nhis", [])
    stale_credentials = enrichment.get("stale_credentials", [])
    correlations = enrichment.get("correlations", [])

    # Build context for LLM
    context_lines = [
        "## Discovered Identities",
    ]
    for identity in state.identities_discovered[:30]:
        context_lines.append(
            f"- {identity.identity_id} ({identity.identity_type}): "
            f"permissions={identity.permissions[:5]}, "
            f"mfa={identity.mfa_enabled}, groups={identity.groups}"
        )

    context_lines.append(f"\n## Trust Relationships ({len(state.relationships_mapped)})")
    for rel in state.relationships_mapped[:20]:
        context_lines.append(
            f"- {rel.source_id} -> {rel.target_id} ({rel.relationship_type}), "
            f"scope={rel.scope}, trust={rel.trust_level}"
        )

    context_lines.append(f"\n## Trust Chains ({len(state.trust_chains)})")
    for chain in state.trust_chains[:10]:
        context_lines.append(f"- {' -> '.join(chain)}")

    user_prompt = "\n".join(context_lines)

    risk_assessments: list[RiskAssessment] = []
    over_privileged: list[dict[str, Any]] = []
    stale: list[dict[str, Any]] = []
    lateral_paths: list[list[str]] = []
    credential_risks: list[dict[str, Any]] = state.credential_risks[:]

    # NHI-enhanced risk assessment (LLM with heuristic fallback)
    if nhis or stale_credentials:
        nhi_risk_result = await toolkit.assess_identity_risk_llm(
            nhis,
            stale_credentials,
            correlations,
        )
        for hri in nhi_risk_result.get("high_risk_identities", []):
            risk_assessments.append(
                RiskAssessment(
                    entity_id=hri,
                    risk_score=75.0,
                    risk_factors=nhi_risk_result.get("risk_factors", [])[:3],
                    recommended_action="restrict",
                )
            )
        over_privileged.extend(nhi_risk_result.get("over_privileged_accounts", []))
        stale.extend(
            [
                {"identity_id": s.get("identity_id", ""), "reason": "stale_credentials"}
                for s in nhi_risk_result.get("stale_accounts", [])
            ]
        )

    # Standard LLM risk assessment
    try:
        risk_result = cast(
            IdentityRiskResult,
            await llm_structured(
                system_prompt=SYSTEM_IDENTITY_RISK_ASSESSMENT,
                user_prompt=user_prompt,
                schema=IdentityRiskResult,
            ),
        )

        for identity_id in risk_result.high_risk_identities:
            # Avoid duplicates from NHI assessment
            existing_ids = {ra.entity_id for ra in risk_assessments}
            if identity_id not in existing_ids:
                risk_assessments.append(
                    RiskAssessment(
                        entity_id=identity_id,
                        risk_score=75.0,
                        risk_factors=risk_result.risk_factors[:3],
                        recommended_action="restrict",
                    )
                )

        over_privileged.extend(risk_result.over_privileged)
        stale.extend(
            [
                {"identity_id": cid, "reason": "stale_credentials"}
                for cid in risk_result.stale_credentials
            ]
        )

        # Lateral movement analysis
        lateral_result = cast(
            LateralMovementResult,
            await llm_structured(
                system_prompt=SYSTEM_LATERAL_MOVEMENT_ANALYSIS,
                user_prompt=user_prompt,
                schema=LateralMovementResult,
            ),
        )
        lateral_paths = lateral_result.paths
        credential_risks.extend(
            [
                {"identity_id": cp, "risk": "lateral_movement_choke_point"}
                for cp in lateral_result.choke_points
            ]
        )

        output_summary = (
            f"Risk: {risk_result.risk_summary[:150]}. "
            f"{len(over_privileged)} over-privileged, "
            f"{len(lateral_paths)} lateral movement paths, "
            f"{len(nhis)} NHIs assessed"
        )
    except Exception as e:
        logger.error("identity_graph.risk_assessment_failed", error=str(e))
        output_summary = f"Risk assessment failed (using heuristic fallback): {e}"

        # Fallback: flag identities without MFA and over-privileged
        for identity in state.identities_discovered:
            existing_ids = {ra.entity_id for ra in risk_assessments}
            if identity.identity_id in existing_ids:
                continue
            if not identity.mfa_enabled and identity.identity_type == "human":
                risk_assessments.append(
                    RiskAssessment(
                        entity_id=identity.identity_id,
                        risk_score=50.0,
                        risk_factors=["no_mfa"],
                        recommended_action="require_mfa",
                    )
                )
            if len(identity.permissions) > 5:
                over_privileged.append(
                    {
                        "identity_id": identity.identity_id,
                        "permissions_count": len(identity.permissions),
                    }
                )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="assess_risks",
        input_summary=(
            f"Assessing {len(state.identities_discovered)} identities, "
            f"{len(state.trust_chains)} chains, {len(nhis)} NHIs"
        ),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="llm+nhi_assessment",
    )

    return {
        "risk_assessments": risk_assessments,
        "over_privileged_identities": over_privileged,
        "stale_grants": stale,
        "lateral_movement_paths": lateral_paths,
        "credential_risks": credential_risks,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_risks",
    }


async def generate_remediations(state: IdentityGraphState) -> dict[str, Any]:
    """Generate remediation actions using LLM analysis."""
    start = datetime.now(UTC)

    logger.info(
        "identity_graph.generating_remediations",
        risks=len(state.risk_assessments),
        over_privileged=len(state.over_privileged_identities),
    )

    context_lines = [
        "## Risk Assessments",
    ]
    for ra in state.risk_assessments[:20]:
        context_lines.append(
            f"- {ra.entity_id}: score={ra.risk_score}, "
            f"factors={ra.risk_factors}, action={ra.recommended_action}"
        )

    context_lines.append(
        f"\n## Over-Privileged Identities ({len(state.over_privileged_identities)})"
    )
    for op in state.over_privileged_identities[:10]:
        context_lines.append(f"- {op}")

    context_lines.append(f"\n## Lateral Movement Paths ({len(state.lateral_movement_paths)})")
    for path in state.lateral_movement_paths[:10]:
        context_lines.append(f"- {' -> '.join(path)}")

    context_lines.append(f"\n## Credential Risks ({len(state.credential_risks)})")
    for cr in state.credential_risks[:10]:
        context_lines.append(f"- {cr}")

    user_prompt = "\n".join(context_lines)

    remediation_actions: list[dict[str, Any]] = []
    policy_updates: list[dict[str, Any]] = []

    try:
        result = cast(
            RemediationPlanResult,
            await llm_structured(
                system_prompt=SYSTEM_REMEDIATION_GENERATION,
                user_prompt=user_prompt,
                schema=RemediationPlanResult,
            ),
        )
        remediation_actions = result.actions
        policy_updates = result.policy_updates
        output_summary = (
            f"{result.summary[:150]}. Est. risk reduction: {result.estimated_risk_reduction_pct}%"
        )
    except Exception as e:
        logger.error("identity_graph.remediation_generation_failed", error=str(e))
        output_summary = f"Remediation generation failed: {e}"
        # Fallback
        for ra in state.risk_assessments:
            remediation_actions.append(
                {
                    "target": ra.entity_id,
                    "action_type": ra.recommended_action,
                    "priority": "high" if ra.risk_score >= 70 else "medium",
                }
            )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_remediations",
        input_summary=f"Generating remediations for {len(state.risk_assessments)} risk findings",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="llm",
    )

    return {
        "remediation_actions": remediation_actions,
        "policy_updates": policy_updates,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "generate_remediations",
    }


async def report(state: IdentityGraphState) -> dict[str, Any]:
    """Generate final report summary and persist results."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    session_duration = 0
    if state.session_start:
        session_duration = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    output_summary = (
        f"Scan complete: {len(state.identities_discovered)} identities, "
        f"{len(state.relationships_mapped)} relationships, "
        f"{len(state.risk_assessments)} risks, "
        f"{len(state.remediation_actions)} remediations, "
        f"{len(state.credential_risks)} credential risks"
    )

    # Persist scan results
    await toolkit.persist_scan_result(
        scan_target=state.scan_target,
        result={
            "identities": len(state.identities_discovered),
            "relationships": len(state.relationships_mapped),
            "risks": len(state.risk_assessments),
            "remediations": len(state.remediation_actions),
            "credential_risks": len(state.credential_risks),
            "over_privileged": len(state.over_privileged_identities),
            "stale_grants": len(state.stale_grants),
        },
        duration_ms=session_duration,
        error=state.error or None,
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="report",
        input_summary="Compiling final identity graph report",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
    )

    return {
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
        "session_duration_ms": session_duration,
    }
