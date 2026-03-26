"""Tool functions for the Threat Intelligence Platform.

Bridges multi-source intelligence feeds, STIX/TAXII
normalization, cross-source correlation, relevance
scoring, and advisory generation to the LangGraph nodes.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.threat_intelligence_platform.models import (
    IntelligenceItem,
    IntelSource,
    NormalizedIndicator,
    RelevanceAssessment,
    ThreatAdvisory,
    ThreatCorrelation,
    ThreatRelevance,
)

logger = structlog.get_logger()


class ThreatIntelligencePlatformToolkit:
    """Tools for the threat intelligence platform agent.

    Injected into nodes at graph construction time to
    decouple agent logic from feed/connector implementations.
    """

    def __init__(
        self,
        feed_clients: dict[str, Any] | None = None,
        siem_client: Any = None,
        dark_web_client: Any = None,
        stix_client: Any = None,
        notification_client: Any = None,
        environment_profile: dict[str, Any] | None = None,
    ) -> None:
        self._feed_clients = feed_clients or {}
        self._siem_client = siem_client
        self._dark_web_client = dark_web_client
        self._stix_client = stix_client
        self._notification_client = notification_client
        self._env_profile = environment_profile or {}

    # ---- Collection ----

    async def collect_intelligence(
        self,
        sources: list[IntelSource],
        tenant_id: str = "",
    ) -> list[IntelligenceItem]:
        """Collect raw intelligence from configured feeds.

        Args:
            sources: Intelligence sources to query.
            tenant_id: Tenant for scoping queries.

        Returns:
            List of raw IntelligenceItem objects.
        """
        items: list[IntelligenceItem] = []
        now = datetime.now(UTC)

        for source in sources:
            client = self._feed_clients.get(source.value)
            if client is None:
                logger.warning(
                    "tip_feed_not_configured",
                    source=source.value,
                )
                continue

            try:
                raw_items = await client.fetch(tenant_id=tenant_id)
                for raw in raw_items:
                    items.append(
                        IntelligenceItem(
                            item_id=raw.get(
                                "id",
                                f"item-{uuid4().hex[:8]}",
                            ),
                            source=source,
                            raw_type=raw.get("type", ""),
                            raw_value=raw.get("value", ""),
                            raw_context=raw.get("context", ""),
                            collected_at=raw.get("timestamp", now),
                            feed_name=raw.get("feed", source.value),
                            tags=raw.get("tags", []),
                            mitre_tactics=raw.get("mitre_tactics", []),
                            confidence_raw=raw.get("confidence", 0.0),
                            metadata=raw.get("metadata", {}),
                        )
                    )
            except Exception as e:
                logger.error(
                    "tip_collection_failed",
                    source=source.value,
                    error=str(e),
                )

        logger.info(
            "tip_collection_complete",
            sources=[s.value for s in sources],
            items_collected=len(items),
        )
        return items

    # ---- Normalization ----

    async def normalize_to_stix(
        self,
        items: list[IntelligenceItem],
    ) -> list[NormalizedIndicator]:
        """Normalize raw items to STIX/TAXII format.

        Maps raw indicator types to STIX observable types,
        assigns patterns, and deduplicates across sources.

        Args:
            items: Raw intelligence items.

        Returns:
            List of NormalizedIndicator objects.
        """
        indicators: list[NormalizedIndicator] = []
        seen_values: set[str] = set()

        type_map = {
            "ip": ("ipv4-addr", "ipv4-addr:value = "),
            "ipv4": ("ipv4-addr", "ipv4-addr:value = "),
            "ipv6": ("ipv6-addr", "ipv6-addr:value = "),
            "domain": (
                "domain-name",
                "domain-name:value = ",
            ),
            "url": ("url", "url:value = "),
            "hash": (
                "file",
                "file:hashes.'SHA-256' = ",
            ),
            "md5": ("file", "file:hashes.MD5 = "),
            "sha256": (
                "file",
                "file:hashes.'SHA-256' = ",
            ),
            "email": (
                "email-addr",
                "email-addr:value = ",
            ),
            "cve": (
                "vulnerability",
                "vulnerability:name = ",
            ),
        }

        for item in items:
            if item.raw_value in seen_values:
                continue
            seen_values.add(item.raw_value)

            raw_lower = item.raw_type.lower()
            stix_info = type_map.get(
                raw_lower,
                ("artifact", "artifact:payload_bin = "),
            )

            pattern = f"[{stix_info[1]}'{item.raw_value}']"

            indicators.append(
                NormalizedIndicator(
                    indicator_id=(f"ind-{uuid4().hex[:8]}"),
                    stix_type=stix_info[0],
                    stix_pattern=pattern,
                    value=item.raw_value,
                    indicator_types=[item.raw_type],
                    source=item.source,
                    confidence=item.confidence_raw,
                    valid_from=item.collected_at,
                    kill_chain_phases=(item.mitre_tactics),
                    labels=item.tags,
                )
            )

        logger.info(
            "tip_normalization_complete",
            raw_count=len(items),
            normalized_count=len(indicators),
            dedup_removed=len(items) - len(indicators),
        )
        return indicators

    # ---- Correlation ----

    async def correlate_cross_source(
        self,
        indicators: list[NormalizedIndicator],
    ) -> list[ThreatCorrelation]:
        """Correlate indicators across sources and internal.

        Links indicators seen in multiple feeds, checks
        against internal SIEM/telemetry for matches.

        Args:
            indicators: Normalized STIX indicators.

        Returns:
            List of ThreatCorrelation results.
        """
        correlations: list[ThreatCorrelation] = []

        # Group indicators by value for cross-source
        by_value: dict[str, list[NormalizedIndicator]] = {}
        for ind in indicators:
            by_value.setdefault(ind.value, []).append(ind)

        for value, inds in by_value.items():
            sources_matched = list({i.source for i in inds})
            ind_ids = [i.indicator_id for i in inds]

            # Internal correlation via SIEM
            matches: list[dict[str, Any]] = []
            entities: list[str] = []
            if self._siem_client is not None:
                try:
                    siem_hits = await self._siem_client.search(
                        value,
                        indicator_type=(inds[0].stix_type),
                    )
                    matches.extend(siem_hits.get("matches", []))
                    entities.extend(siem_hits.get("entities", []))
                except Exception as e:
                    logger.error(
                        "tip_siem_correlation_failed",
                        indicator=value,
                        error=str(e),
                    )

            risk_score = self._calculate_risk(
                match_count=len(matches),
                source_count=len(sources_matched),
                has_kill_chain=bool(inds[0].kill_chain_phases),
            )

            correlations.append(
                ThreatCorrelation(
                    correlation_id=(f"corr-{uuid4().hex[:8]}"),
                    indicator_ids=ind_ids,
                    sources_matched=sources_matched,
                    internal_matches=matches,
                    match_count=len(matches),
                    risk_score=risk_score,
                    entities_affected=list(set(entities)),
                )
            )

        logger.info(
            "tip_correlation_complete",
            indicators=len(indicators),
            correlations=len(correlations),
            total_matches=sum(c.match_count for c in correlations),
        )
        return correlations

    # ---- Relevance Assessment ----

    async def assess_relevance(
        self,
        indicator: NormalizedIndicator,
        correlation: ThreatCorrelation,
    ) -> RelevanceAssessment:
        """Score indicator relevance to customer env.

        Combines confidence, correlation data, kill chain,
        and environment profile for relevance scoring.

        Args:
            indicator: STIX normalized indicator.
            correlation: Correlation result.

        Returns:
            RelevanceAssessment with score and actions.
        """
        # Base from confidence
        base = indicator.confidence

        # Boost for multiple sources
        src_boost = min(
            len(correlation.sources_matched) * 0.05,
            0.15,
        )

        # Boost for internal matches
        match_boost = min(correlation.match_count * 0.1, 0.3)

        # Boost for kill chain coverage
        kc_boost = 0.1 if indicator.kill_chain_phases else 0.0

        score = min(
            base + src_boost + match_boost + kc_boost,
            1.0,
        )

        relevance = self._score_to_relevance(score)
        actionable = score >= 0.4

        actions: list[str] = []
        drp_flags: list[str] = []

        if actionable:
            actions.append(f"block_{indicator.stix_type}")
            if correlation.match_count > 0:
                actions.append("investigate_internal_matches")
            if indicator.kill_chain_phases:
                actions.append("update_detection_rules")
            if len(correlation.sources_matched) > 2:
                actions.append("escalate_multi_source_threat")

        # Digital risk protection checks
        if "brand" in " ".join(indicator.labels):
            drp_flags.append("brand_impersonation")
        if "leak" in " ".join(indicator.labels):
            drp_flags.append("data_leak_detected")
        if "credential" in " ".join(indicator.labels):
            drp_flags.append("credential_exposure")

        ttl_map = {
            ThreatRelevance.IMMEDIATE: 336,
            ThreatRelevance.HIGH: 168,
            ThreatRelevance.MODERATE: 72,
            ThreatRelevance.LOW: 24,
            ThreatRelevance.INFORMATIONAL: 6,
        }

        return RelevanceAssessment(
            indicator_id=indicator.indicator_id,
            relevance=relevance,
            relevance_score=score,
            actionable=actionable,
            exposure_vectors=[indicator.stix_type],
            recommended_actions=actions,
            ttl_hours=ttl_map.get(relevance, 24),
            digital_risk_flags=drp_flags,
        )

    # ---- Advisory Generation ----

    async def generate_advisories(
        self,
        assessments: list[RelevanceAssessment],
        correlations: list[ThreatCorrelation],
        indicators: list[NormalizedIndicator],
    ) -> list[ThreatAdvisory]:
        """Generate threat advisories from assessments.

        Groups related indicators into advisory bundles,
        prioritized by severity.

        Args:
            assessments: Relevance assessments.
            correlations: Correlation data.
            indicators: Normalized indicators.

        Returns:
            List of ThreatAdvisory objects.
        """
        now = datetime.now(UTC)
        advisories: list[ThreatAdvisory] = []

        # Build lookup maps
        ind_map = {i.indicator_id: i for i in indicators}
        _assess_map = {a.indicator_id: a for a in assessments}

        # Group actionable assessments by severity
        by_severity: dict[ThreatRelevance, list[RelevanceAssessment]] = {}
        for a in assessments:
            if a.actionable:
                by_severity.setdefault(a.relevance, []).append(a)

        severity_order = [
            ThreatRelevance.IMMEDIATE,
            ThreatRelevance.HIGH,
            ThreatRelevance.MODERATE,
            ThreatRelevance.LOW,
        ]

        for severity in severity_order:
            group = by_severity.get(severity, [])
            if not group:
                continue

            ind_ids = [a.indicator_id for a in group]
            all_actions: list[str] = []
            all_techniques: list[str] = []
            for a in group:
                all_actions.extend(a.recommended_actions)
                ind = ind_map.get(a.indicator_id)
                if ind and ind.kill_chain_phases:
                    all_techniques.extend(ind.kill_chain_phases)

            targets = ["soc_team"]
            if severity in (
                ThreatRelevance.IMMEDIATE,
                ThreatRelevance.HIGH,
            ):
                targets.extend(["ciso", "incident_response"])

            advisories.append(
                ThreatAdvisory(
                    advisory_id=(f"adv-{uuid4().hex[:8]}"),
                    title=(f"{severity.value.title()} Threat Advisory: {len(group)} indicators"),
                    severity=severity,
                    summary=(
                        f"{len(group)} {severity.value}"
                        f" indicators identified "
                        f"across "
                        f"{len({a.indicator_id for a in group})} "
                        f"unique IOCs."
                    ),
                    affected_indicators=ind_ids,
                    recommended_actions=list(set(all_actions)),
                    mitre_techniques=list(set(all_techniques)),
                    distribution_targets=targets,
                    generated_at=now,
                )
            )

        logger.info(
            "tip_advisories_generated",
            advisory_count=len(advisories),
            total_actionable=sum(1 for a in assessments if a.actionable),
        )
        return advisories

    # ---- Private helpers ----

    @staticmethod
    def _calculate_risk(
        match_count: int,
        source_count: int,
        has_kill_chain: bool,
    ) -> float:
        """Calculate 0-10 risk score."""
        score = 1.0
        score += min(match_count * 0.5, 2.5)
        score += min(source_count * 1.0, 3.0)
        if has_kill_chain:
            score += 1.5
        return min(score, 10.0)

    @staticmethod
    def _score_to_relevance(
        score: float,
    ) -> ThreatRelevance:
        """Map 0-1 relevance score to enum."""
        if score >= 0.9:
            return ThreatRelevance.IMMEDIATE
        if score >= 0.7:
            return ThreatRelevance.HIGH
        if score >= 0.5:
            return ThreatRelevance.MODERATE
        if score >= 0.3:
            return ThreatRelevance.LOW
        return ThreatRelevance.INFORMATIONAL
