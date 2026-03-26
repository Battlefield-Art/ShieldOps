"""Tool functions for the Trust Relationship Mapper Agent."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.trust_relationship_mapper.models import (
    AbuseIndicator,
    DelegationChain,
    FederationMapping,
    TrustAbuse,
    TrustBoundary,
    TrustRiskAssessment,
    TrustType,
)

logger = structlog.get_logger()


class TrustRelationshipMapperToolkit:
    """Toolkit for trust relationship mapping."""

    def __init__(
        self,
        identity_sources: Any | None = None,
        federation_scanner: Any | None = None,
        cloud_connectors: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._identity_sources = identity_sources
        self._federation_scanner = federation_scanner
        self._cloud_connectors = cloud_connectors
        self._policy_engine = policy_engine
        self._repository = repository

    async def discover_trust_boundaries(
        self,
        tenant_id: str,
        scope: str = "all",
    ) -> list[TrustBoundary]:
        """Discover trust boundaries across infra."""
        logger.info(
            "trust_mapper.discover",
            tenant_id=tenant_id,
            scope=scope,
        )
        if self._identity_sources is not None:
            try:
                return await self._identity_sources.discover(tenant_id, scope)
            except Exception:
                logger.warning("trust_mapper.discover_fallback")
        return []

    async def map_federation(
        self,
        boundaries: list[TrustBoundary],
    ) -> list[FederationMapping]:
        """Map federation relationships."""
        logger.info(
            "trust_mapper.map_federation",
            count=len(boundaries),
        )
        mappings: list[FederationMapping] = []
        for b in boundaries:
            if b.trust_type != TrustType.FEDERATION:
                continue
            mappings.append(
                FederationMapping(
                    id=f"fed-{uuid4().hex[:8]}",
                    source_idp=b.source_domain,
                    target_sp=b.target_domain,
                    protocol=b.protocol,
                    last_token_issued=b.last_used,
                )
            )
        return mappings

    async def analyze_delegation_chains(
        self,
        boundaries: list[TrustBoundary],
    ) -> list[DelegationChain]:
        """Analyze delegation chains for depth."""
        logger.info(
            "trust_mapper.analyze_delegation",
            count=len(boundaries),
        )
        delegation_bounds = [
            b
            for b in boundaries
            if b.trust_type
            in (
                TrustType.DELEGATION,
                TrustType.AI_AGENT_DELEGATION,
                TrustType.MCP_TRUST_CHAIN,
            )
        ]
        chains: list[DelegationChain] = []
        for b in delegation_bounds:
            chains.append(
                DelegationChain(
                    id=f"del-{uuid4().hex[:8]}",
                    chain_depth=1,
                    principals=[
                        b.source_domain,
                        b.target_domain,
                    ],
                    trust_types=[b.trust_type],
                    is_transitive=(b.is_bidirectional),
                )
            )
        return chains

    async def detect_trust_abuse(
        self,
        boundaries: list[TrustBoundary],
        federations: list[FederationMapping],
        chains: list[DelegationChain],
    ) -> list[TrustAbuse]:
        """Detect trust abuse indicators."""
        logger.info(
            "trust_mapper.detect_abuse",
            boundaries=len(boundaries),
            federations=len(federations),
            chains=len(chains),
        )
        abuses: list[TrustAbuse] = []

        # Detect stale federations
        for fed in federations:
            if fed.token_count_30d == 0:
                abuses.append(
                    TrustAbuse(
                        id=(f"abuse-{uuid4().hex[:8]}"),
                        indicator=(AbuseIndicator.STALE_FEDERATION),
                        trust_boundary_id=fed.id,
                        severity="medium",
                        description=(f"Stale federation: {fed.source_idp} -> {fed.target_sp}"),
                        recommended_action=("Review and remove if unused"),
                    )
                )

        # Detect excessive delegation
        for chain in chains:
            if chain.chain_depth > 2:
                abuses.append(
                    TrustAbuse(
                        id=(f"abuse-{uuid4().hex[:8]}"),
                        indicator=(AbuseIndicator.EXCESSIVE_DELEGATION),
                        trust_boundary_id=chain.id,
                        severity="high",
                        description=(f"Delegation chain depth {chain.chain_depth}"),
                        recommended_action=("Reduce delegation chain depth"),
                    )
                )

        return abuses

    async def assess_trust_risk(
        self,
        boundaries: list[TrustBoundary],
        abuses: list[TrustAbuse],
    ) -> list[TrustRiskAssessment]:
        """Assess risk for each trust boundary."""
        logger.info(
            "trust_mapper.assess_risk",
            boundaries=len(boundaries),
            abuses=len(abuses),
        )
        abuse_map: dict[str, list[TrustAbuse]] = {}
        for abuse in abuses:
            abuse_map.setdefault(abuse.trust_boundary_id, []).append(abuse)

        assessments: list[TrustRiskAssessment] = []
        for b in boundaries:
            b_abuses = abuse_map.get(b.id, [])
            risk = min(len(b_abuses) * 0.3, 1.0)
            factors = [a.description for a in b_abuses]
            indicators = [a.indicator for a in b_abuses]
            priority = "low"
            if risk >= 0.8:
                priority = "critical"
            elif risk >= 0.6:
                priority = "high"
            elif risk >= 0.3:
                priority = "medium"
            assessments.append(
                TrustRiskAssessment(
                    id=f"risk-{uuid4().hex[:8]}",
                    trust_boundary_id=b.id,
                    overall_risk=risk,
                    risk_factors=factors,
                    abuse_indicators=indicators,
                    recommendation=("Review trust relationship"),
                    remediation_priority=priority,
                )
            )
        return assessments
