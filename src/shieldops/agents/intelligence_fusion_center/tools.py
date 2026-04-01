"""Tool functions for the Intelligence Fusion Center.

Bridges multi-source intelligence feeds, cross-source
correlation, intelligence fusion, threat assessment,
and unified assessment generation to the LangGraph nodes.
"""

from __future__ import annotations

import random  # noqa: S311
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.intelligence_fusion_center.models import (
    CorrelatedThreat,
    FusionReport,
    FusionResult,
    IntelFeed,
    IntelSource,
    ThreatAssessment,
    ThreatLevel,
)

logger = structlog.get_logger()


class IntelligenceFusionCenterToolkit:
    """Tools for the intelligence fusion center agent.

    Injected into nodes at graph construction time to
    decouple agent logic from feed/connector implementations.
    """

    def __init__(
        self,
        feed_clients: dict[str, Any] | None = None,
        siem_client: Any = None,
        correlation_client: Any = None,
        notification_client: Any = None,
        environment_profile: dict[str, Any] | None = None,
    ) -> None:
        self._feed_clients = feed_clients or {}
        self._siem_client = siem_client
        self._correlation_client = correlation_client
        self._notification_client = notification_client
        self._env_profile = environment_profile or {}
        self._metrics: list[dict[str, Any]] = []

    # ---- Feed Collection ----

    async def collect_feeds(
        self,
        sources: list[IntelSource] | None = None,
        tenant_id: str = "",
    ) -> list[IntelFeed]:
        """Collect raw intelligence from configured feeds.

        Args:
            sources: Intelligence sources to query.
            tenant_id: Tenant for scoping queries.

        Returns:
            List of IntelFeed objects.
        """
        if sources is None:
            sources = [IntelSource.OSINT, IntelSource.INTERNAL_TELEMETRY]

        feeds: list[IntelFeed] = []
        now = datetime.now(UTC)

        for source in sources:
            client = self._feed_clients.get(source.value)
            if client is not None:
                try:
                    raw_items = await client.fetch(tenant_id=tenant_id)
                    for raw in raw_items:
                        feeds.append(
                            IntelFeed(
                                feed_id=raw.get("id", f"feed-{uuid4().hex[:8]}"),
                                source=source,
                                feed_name=raw.get("feed", source.value),
                                indicator_type=raw.get("type", ""),
                                indicator_value=raw.get("value", ""),
                                raw_context=raw.get("context", ""),
                                collected_at=raw.get("timestamp", now),
                                confidence=raw.get("confidence", 0.0),
                                tags=raw.get("tags", []),
                                mitre_tactics=raw.get("mitre_tactics", []),
                                metadata=raw.get("metadata", {}),
                            )
                        )
                except Exception as e:
                    logger.error(
                        "ifc_feed_collection_failed",
                        source=source.value,
                        error=str(e),
                    )
            else:
                # Mock feed data for unconfigured sources
                mock_types = ["ip", "domain", "hash", "url", "email"]
                for i in range(random.randint(3, 8)):  # noqa: S311
                    feeds.append(
                        IntelFeed(
                            feed_id=f"feed-{uuid4().hex[:8]}",
                            source=source,
                            feed_name=f"{source.value}_feed",
                            indicator_type=random.choice(mock_types),  # noqa: S311
                            indicator_value=f"mock-{source.value}-{i}-{uuid4().hex[:6]}",
                            raw_context=f"Mock intel from {source.value}",
                            collected_at=now,
                            confidence=round(random.uniform(0.3, 0.95), 2),  # noqa: S311
                            tags=[source.value, "auto-collected"],
                            mitre_tactics=random.sample(  # noqa: S311
                                [
                                    "TA0001",
                                    "TA0002",
                                    "TA0003",
                                    "TA0005",
                                    "TA0007",
                                    "TA0011",
                                ],
                                k=random.randint(1, 3),  # noqa: S311
                            ),
                            metadata={"mock": True},
                        )
                    )

        logger.info(
            "ifc_feeds_collected",
            sources=[s.value for s in sources],
            feeds_collected=len(feeds),
        )
        return feeds

    # ---- Threat Correlation ----

    async def correlate_threats(
        self,
        feeds: list[IntelFeed],
    ) -> list[CorrelatedThreat]:
        """Correlate indicators across sources.

        Groups feeds by indicator value and identifies
        cross-source matches with risk scoring.

        Args:
            feeds: Collected intelligence feeds.

        Returns:
            List of CorrelatedThreat results.
        """
        correlations: list[CorrelatedThreat] = []

        # Group by indicator value for cross-source matching
        by_value: dict[str, list[IntelFeed]] = {}
        for feed in feeds:
            by_value.setdefault(feed.indicator_value, []).append(feed)

        campaign_names = [
            "APT-SHADOW",
            "CRIMSON-TIDE",
            "GHOST-NET",
            "SILENT-STORM",
            "DARK-PULSE",
        ]
        actor_names = [
            "Lazarus",
            "APT28",
            "Sandworm",
            "Turla",
            "Unknown",
        ]

        for _value, feed_group in by_value.items():
            sources_matched = list({f.source for f in feed_group})
            feed_ids = [f.feed_id for f in feed_group]

            risk_score = self._calculate_risk(
                source_count=len(sources_matched),
                avg_confidence=sum(f.confidence for f in feed_group) / len(feed_group),
                has_tactics=any(f.mitre_tactics for f in feed_group),
            )

            correlations.append(
                CorrelatedThreat(
                    correlation_id=f"corr-{uuid4().hex[:8]}",
                    indicator_ids=feed_ids,
                    sources_matched=sources_matched,
                    match_count=len(feed_group),
                    risk_score=risk_score,
                    campaign_name=(
                        random.choice(campaign_names) if len(sources_matched) > 1 else ""  # noqa: S311
                    ),
                    threat_actor=(random.choice(actor_names) if risk_score > 5.0 else ""),  # noqa: S311
                    attack_pattern=(
                        feed_group[0].mitre_tactics[0] if feed_group[0].mitre_tactics else ""
                    ),
                    entities_affected=[
                        f"asset-{uuid4().hex[:4]}"
                        for _ in range(random.randint(0, 3))  # noqa: S311
                    ],
                    temporal_window_hours=random.choice([6, 12, 24, 48, 72]),  # noqa: S311
                )
            )

        logger.info(
            "ifc_threats_correlated",
            feeds=len(feeds),
            correlations=len(correlations),
            multi_source=sum(1 for c in correlations if len(c.sources_matched) > 1),
        )
        return correlations

    # ---- Intelligence Fusion ----

    async def fuse_intelligence(
        self,
        correlations: list[CorrelatedThreat],
        feeds: list[IntelFeed],
    ) -> list[FusionResult]:
        """Fuse correlated threats into unified intelligence.

        Merges correlations with Diamond Model context,
        kill chain mapping, and source agreement analysis.

        Args:
            correlations: Correlated threat results.
            feeds: Original collected feeds.

        Returns:
            List of FusionResult objects.
        """
        results: list[FusionResult] = []

        feed_map: dict[str, IntelFeed] = {f.feed_id: f for f in feeds}

        for corr in correlations:
            # Calculate source agreement
            total_sources = len(IntelSource)
            agreement = len(corr.sources_matched) / total_sources

            # Gather kill chain phases from feeds
            kc_phases: list[str] = []
            for fid in corr.indicator_ids:
                feed = feed_map.get(fid)
                if feed and feed.mitre_tactics:
                    kc_phases.extend(feed.mitre_tactics)
            kc_phases = list(set(kc_phases))

            # Unified confidence from risk + agreement
            unified_conf = min(
                (corr.risk_score / 10.0) * 0.6 + agreement * 0.4,
                1.0,
            )

            # Diamond Model
            diamond = {
                "adversary": corr.threat_actor or "Unknown",
                "capability": corr.attack_pattern or "Unknown",
                "infrastructure": f"{corr.match_count} indicators",
                "victim": corr.entities_affected[:3] if corr.entities_affected else ["Unknown"],
            }

            # Intelligence gaps
            gaps: list[str] = []
            if not corr.threat_actor:
                gaps.append("threat_actor_attribution")
            if not kc_phases:
                gaps.append("kill_chain_mapping")
            if agreement < 0.3:
                gaps.append("low_source_agreement")

            results.append(
                FusionResult(
                    fusion_id=f"fusion-{uuid4().hex[:8]}",
                    correlated_threat_ids=[corr.correlation_id],
                    unified_confidence=round(unified_conf, 3),
                    threat_narrative=(
                        f"Threat actor {corr.threat_actor or 'unknown'} "
                        f"campaign {corr.campaign_name or 'unnamed'} — "
                        f"{corr.match_count} indicators across "
                        f"{len(corr.sources_matched)} sources."
                    ),
                    kill_chain_coverage=kc_phases,
                    diamond_model=diamond,
                    source_agreement_ratio=round(agreement, 3),
                    fused_indicators=[
                        {"id": fid, "source": feed_map.get(fid, IntelFeed()).source.value}
                        for fid in corr.indicator_ids
                    ],
                    intelligence_gaps=gaps,
                )
            )

        logger.info(
            "ifc_intelligence_fused",
            correlations=len(correlations),
            fusions=len(results),
            avg_confidence=round(
                sum(r.unified_confidence for r in results) / max(len(results), 1),
                3,
            ),
        )
        return results

    # ---- Threat Assessment ----

    async def assess_threats(
        self,
        fusions: list[FusionResult],
    ) -> list[ThreatAssessment]:
        """Assess fused intelligence against environment.

        Scores each fusion result by threat level,
        actionability, and exposure.

        Args:
            fusions: Fused intelligence results.

        Returns:
            List of ThreatAssessment objects.
        """
        assessments: list[ThreatAssessment] = []

        for fusion in fusions:
            score = fusion.unified_confidence

            # Boost for strong kill chain coverage
            kc_boost = min(len(fusion.kill_chain_coverage) * 0.05, 0.2)
            score = min(score + kc_boost, 1.0)

            threat_level = self._score_to_threat_level(score)
            actionable = score >= 0.4

            actions: list[str] = []
            if actionable:
                actions.append("update_detection_rules")
                if score >= 0.7:
                    actions.append("escalate_to_incident_response")
                    actions.append("block_indicators")
                if fusion.intelligence_gaps:
                    actions.append("task_additional_collection")
                if fusion.source_agreement_ratio > 0.5:
                    actions.append("distribute_to_peers")

            ttl_map = {
                ThreatLevel.CRITICAL: 336,
                ThreatLevel.HIGH: 168,
                ThreatLevel.MEDIUM: 72,
                ThreatLevel.LOW: 24,
                ThreatLevel.INFORMATIONAL: 6,
            }

            assessments.append(
                ThreatAssessment(
                    assessment_id=f"assess-{uuid4().hex[:8]}",
                    fusion_id=fusion.fusion_id,
                    threat_level=threat_level,
                    overall_score=round(score, 3),
                    actionable=actionable,
                    exposure_vectors=[v["source"] for v in fusion.fused_indicators[:5]],
                    recommended_actions=actions,
                    mitre_techniques=fusion.kill_chain_coverage,
                    affected_assets=fusion.diamond_model.get("victim", []),
                    ttl_hours=ttl_map.get(threat_level, 24),
                )
            )

        logger.info(
            "ifc_threats_assessed",
            fusions=len(fusions),
            assessments=len(assessments),
            actionable=sum(1 for a in assessments if a.actionable),
        )
        return assessments

    # ---- Assessment Generation ----

    async def generate_assessment(
        self,
        assessments: list[ThreatAssessment],
        fusions: list[FusionResult],
    ) -> list[FusionReport]:
        """Generate unified assessment reports.

        Groups related assessments into reports by
        threat level for distribution.

        Args:
            assessments: Threat assessments.
            fusions: Fusion results for context.

        Returns:
            List of FusionReport objects.
        """
        now = datetime.now(UTC)
        reports: list[FusionReport] = []

        fusion_map = {f.fusion_id: f for f in fusions}

        # Group actionable assessments by threat level
        by_level: dict[ThreatLevel, list[ThreatAssessment]] = {}
        for a in assessments:
            if a.actionable:
                by_level.setdefault(a.threat_level, []).append(a)

        level_order = [
            ThreatLevel.CRITICAL,
            ThreatLevel.HIGH,
            ThreatLevel.MEDIUM,
            ThreatLevel.LOW,
        ]

        for level in level_order:
            group = by_level.get(level, [])
            if not group:
                continue

            targets = ["soc_team"]
            if level in (ThreatLevel.CRITICAL, ThreatLevel.HIGH):
                targets.extend(["ciso", "incident_response"])

            reports.append(
                FusionReport(
                    report_id=f"rpt-{uuid4().hex[:8]}",
                    title=(f"{level.value.title()} Fusion Assessment: {len(group)} threats"),
                    threat_level=level,
                    executive_summary=(
                        f"{len(group)} {level.value} threats "
                        f"identified via intelligence fusion "
                        f"across {sum(len(a.exposure_vectors) for a in group)} "
                        f"exposure vectors."
                    ),
                    feeds_processed=sum(
                        len(fusion_map.get(a.fusion_id, FusionResult()).fused_indicators)
                        for a in group
                    ),
                    threats_correlated=len(group),
                    fusions_completed=len({a.fusion_id for a in group}),
                    assessments_generated=len(group),
                    actionable_count=sum(1 for a in group if a.actionable),
                    high_priority_count=sum(1 for a in group if a.overall_score >= 0.7),
                    distribution_targets=targets,
                    generated_at=now,
                )
            )

        logger.info(
            "ifc_assessment_generated",
            report_count=len(reports),
            total_actionable=sum(1 for a in assessments if a.actionable),
        )
        return reports

    # ---- Metrics ----

    async def record_metric(
        self,
        metric_name: str,
        value: float,
        tags: dict[str, str] | None = None,
    ) -> None:
        """Record a fusion center metric.

        Args:
            metric_name: Name of the metric.
            value: Metric value.
            tags: Optional tags for the metric.
        """
        self._metrics.append(
            {
                "name": metric_name,
                "value": value,
                "tags": tags or {},
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )
        logger.debug(
            "ifc_metric_recorded",
            metric=metric_name,
            value=value,
        )

    # ---- Private helpers ----

    @staticmethod
    def _calculate_risk(
        source_count: int,
        avg_confidence: float,
        has_tactics: bool,
    ) -> float:
        """Calculate 0-10 risk score."""
        score = 1.0
        score += min(source_count * 1.5, 4.0)
        score += avg_confidence * 3.0
        if has_tactics:
            score += 1.5
        return min(round(score, 2), 10.0)

    @staticmethod
    def _score_to_threat_level(score: float) -> ThreatLevel:
        """Map 0-1 score to ThreatLevel enum."""
        if score >= 0.9:
            return ThreatLevel.CRITICAL
        if score >= 0.7:
            return ThreatLevel.HIGH
        if score >= 0.5:
            return ThreatLevel.MEDIUM
        if score >= 0.3:
            return ThreatLevel.LOW
        return ThreatLevel.INFORMATIONAL
