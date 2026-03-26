"""Tool functions for the Alert Correlation Agent."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.alert_correlation.models import (
    CorrelationCluster,
    CorrelationType,
    RawAlert,
)

logger = structlog.get_logger()


class AlertCorrelationToolkit:
    """Toolkit bridging alert correlation to security data sources and engines."""

    def __init__(
        self,
        alert_sources: Any | None = None,
        correlation_engine: Any | None = None,
        kill_chain_mapper: Any | None = None,
        topology_resolver: Any | None = None,
        identity_resolver: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._alert_sources = alert_sources
        self._correlation_engine = correlation_engine
        self._kill_chain_mapper = kill_chain_mapper
        self._topology_resolver = topology_resolver
        self._identity_resolver = identity_resolver
        self._policy_engine = policy_engine
        self._repository = repository

    async def collect_raw_alerts(
        self,
        tenant_id: str,
        time_window_minutes: int = 60,
    ) -> list[RawAlert]:
        """Collect raw alerts from all configured sources within the time window."""
        logger.info(
            "alert_correlation.collect_raw_alerts",
            tenant_id=tenant_id,
            time_window_minutes=time_window_minutes,
        )
        if self._alert_sources is not None:
            try:
                return await self._alert_sources.collect(tenant_id, time_window_minutes)
            except Exception:
                logger.warning("alert_correlation.collect_fallback")
        return []

    async def normalize_alerts(
        self,
        alerts: list[RawAlert],
    ) -> list[RawAlert]:
        """Normalize alerts to a common schema with unified entity references."""
        logger.info(
            "alert_correlation.normalize_alerts",
            alert_count=len(alerts),
        )
        normalized: list[RawAlert] = []
        for alert in alerts:
            normalized.append(
                RawAlert(
                    id=alert.id or uuid4().hex[:12],
                    source=alert.source.lower().strip(),
                    alert_type=alert.alert_type.lower().strip(),
                    severity=alert.severity.lower().strip(),
                    title=alert.title,
                    description=alert.description,
                    timestamp=alert.timestamp,
                    entities=[e.lower().strip() for e in alert.entities],
                    raw_data=alert.raw_data,
                )
            )
        return normalized

    async def correlate_alerts(
        self,
        alerts: list[RawAlert],
    ) -> list[CorrelationCluster]:
        """Correlate alerts using temporal, causal, and identity-based matching."""
        logger.info(
            "alert_correlation.correlate_alerts",
            alert_count=len(alerts),
        )
        if not alerts:
            return []

        clusters: list[CorrelationCluster] = []

        # Temporal correlation: alerts within 5-minute windows
        temporal_groups = self._group_temporal(alerts, window_seconds=300)
        for group in temporal_groups:
            if len(group) >= 2:
                clusters.append(
                    CorrelationCluster(
                        id=f"clust-{uuid4().hex[:8]}",
                        alert_ids=[a.id for a in group],
                        correlation_type=CorrelationType.TEMPORAL,
                        confidence=min(0.6 + len(group) * 0.05, 0.95),
                        affected_assets=list({e for a in group for e in a.entities}),
                    )
                )

        # Identity-based correlation: shared entities across alerts
        identity_groups = self._group_by_entity(alerts)
        for entity, group in identity_groups.items():
            if len(group) >= 2:
                clusters.append(
                    CorrelationCluster(
                        id=f"clust-{uuid4().hex[:8]}",
                        alert_ids=[a.id for a in group],
                        correlation_type=CorrelationType.IDENTITY_BASED,
                        confidence=min(0.7 + len(group) * 0.05, 0.98),
                        affected_assets=[entity],
                    )
                )

        # Causal correlation: same alert_type from different sources
        causal_groups = self._group_causal(alerts)
        for group in causal_groups:
            if len(group) >= 2:
                clusters.append(
                    CorrelationCluster(
                        id=f"clust-{uuid4().hex[:8]}",
                        alert_ids=[a.id for a in group],
                        correlation_type=CorrelationType.CAUSAL,
                        confidence=min(0.65 + len(group) * 0.05, 0.95),
                        affected_assets=list({e for a in group for e in a.entities}),
                    )
                )

        # Deduplicate clusters that share significant alert overlap
        clusters = self._deduplicate_clusters(clusters)

        if self._correlation_engine is not None:
            try:
                extra = await self._correlation_engine.correlate(alerts)
                clusters.extend(extra)
            except Exception:
                logger.warning("alert_correlation.engine_fallback")

        return clusters

    async def build_kill_chains(
        self,
        clusters: list[CorrelationCluster],
        alerts: list[RawAlert],
    ) -> list[CorrelationCluster]:
        """Enrich clusters with kill chain stage mapping."""
        logger.info(
            "alert_correlation.build_kill_chains",
            cluster_count=len(clusters),
        )
        alert_map = {a.id: a for a in alerts}
        severity_chain_map = {
            "critical": "Actions on Objectives",
            "high": "Lateral Movement",
            "medium": "Exploitation",
            "low": "Reconnaissance",
        }

        enriched: list[CorrelationCluster] = []
        for cluster in clusters:
            cluster_alerts = [alert_map[aid] for aid in cluster.alert_ids if aid in alert_map]
            # Determine kill chain stage from highest-severity alert
            max_sev = "low"
            sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            for a in cluster_alerts:
                if sev_order.get(a.severity, 0) > sev_order.get(max_sev, 0):
                    max_sev = a.severity
            stage = severity_chain_map.get(max_sev, "Unknown")

            enriched.append(
                cluster.model_copy(
                    update={
                        "kill_chain_stage": stage,
                        "correlation_type": (
                            CorrelationType.KILL_CHAIN
                            if len(cluster_alerts) >= 3
                            else cluster.correlation_type
                        ),
                    }
                )
            )
        return enriched

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _group_temporal(
        alerts: list[RawAlert],
        window_seconds: int = 300,
    ) -> list[list[RawAlert]]:
        """Group alerts within temporal windows."""
        if not alerts:
            return []
        sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)
        groups: list[list[RawAlert]] = [[sorted_alerts[0]]]
        for alert in sorted_alerts[1:]:
            if alert.timestamp - groups[-1][0].timestamp <= window_seconds:
                groups[-1].append(alert)
            else:
                groups.append([alert])
        return groups

    @staticmethod
    def _group_by_entity(
        alerts: list[RawAlert],
    ) -> dict[str, list[RawAlert]]:
        """Group alerts by shared entity."""
        entity_map: dict[str, list[RawAlert]] = {}
        for alert in alerts:
            for entity in alert.entities:
                entity_map.setdefault(entity, []).append(alert)
        return entity_map

    @staticmethod
    def _group_causal(alerts: list[RawAlert]) -> list[list[RawAlert]]:
        """Group alerts by alert_type across different sources."""
        type_map: dict[str, list[RawAlert]] = {}
        for alert in alerts:
            type_map.setdefault(alert.alert_type, []).append(alert)
        # Only keep groups with alerts from multiple sources
        return [group for group in type_map.values() if len({a.source for a in group}) >= 2]

    @staticmethod
    def _deduplicate_clusters(
        clusters: list[CorrelationCluster],
    ) -> list[CorrelationCluster]:
        """Remove clusters with >80% alert overlap, keeping higher confidence."""
        if len(clusters) <= 1:
            return clusters
        sorted_clusters = sorted(clusters, key=lambda c: c.confidence, reverse=True)
        kept: list[CorrelationCluster] = []
        for cluster in sorted_clusters:
            alert_set = set(cluster.alert_ids)
            is_duplicate = False
            for existing in kept:
                existing_set = set(existing.alert_ids)
                overlap = len(alert_set & existing_set)
                smaller = min(len(alert_set), len(existing_set))
                if smaller > 0 and overlap / smaller > 0.8:
                    is_duplicate = True
                    break
            if not is_duplicate:
                kept.append(cluster)
        return kept
