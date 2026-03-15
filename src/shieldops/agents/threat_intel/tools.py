"""Tool functions for the Threat Intel Agent.

These bridge threat intelligence feeds, internal observability, and
distribution channels to the agent's LangGraph nodes. Each tool is a
self-contained async function that queries external systems and returns
structured data.
"""

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.threat_intel.models import (
    IntelCorrelation,
    IntelSource,
    ThreatAssessment,
    ThreatConfidence,
    ThreatIndicator,
)

logger = structlog.get_logger()


class ThreatIntelToolkit:
    """Collection of tools available to the threat intel agent.

    Injected into nodes at graph construction time to decouple agent logic
    from specific feed/connector implementations.
    """

    def __init__(
        self,
        feed_clients: dict[str, Any] | None = None,
        siem_client: Any = None,
        firewall_client: Any = None,
        edr_client: Any = None,
        notification_client: Any = None,
    ) -> None:
        self._feed_clients = feed_clients or {}
        self._siem_client = siem_client
        self._firewall_client = firewall_client
        self._edr_client = edr_client
        self._notification_client = notification_client

    async def collect_from_feeds(
        self,
        sources: list[IntelSource],
    ) -> list[ThreatIndicator]:
        """Gather threat indicators from configured intelligence feeds.

        Queries each requested source and returns a consolidated list of
        indicators. Falls back to an empty list for unconfigured sources.

        Args:
            sources: List of intelligence sources to query.

        Returns:
            List of collected ThreatIndicator objects.
        """
        indicators: list[ThreatIndicator] = []
        now = datetime.now(UTC)

        for source in sources:
            client = self._feed_clients.get(source.value)
            if client is None:
                logger.warning(
                    "intel_feed_not_configured",
                    source=source.value,
                )
                continue

            try:
                raw_indicators = await client.fetch_indicators()
                for raw in raw_indicators:
                    indicators.append(
                        ThreatIndicator(
                            value=raw.get("value", ""),
                            indicator_type=raw.get("type", "ip"),
                            source=source,
                            confidence=raw.get("confidence", ThreatConfidence.UNVERIFIED),
                            first_seen=raw.get("first_seen", now),
                            last_seen=raw.get("last_seen", now),
                            tags=raw.get("tags", []),
                            mitre_tactics=raw.get("mitre_tactics", []),
                        )
                    )
            except Exception as e:
                logger.error(
                    "intel_feed_collection_failed",
                    source=source.value,
                    error=str(e),
                )

        logger.info(
            "intel_collection_complete",
            sources_queried=[s.value for s in sources],
            indicators_collected=len(indicators),
        )
        return indicators

    async def correlate_with_internal(
        self,
        indicators: list[ThreatIndicator],
    ) -> list[IntelCorrelation]:
        """Match threat indicators against internal logs and events.

        Queries the SIEM for each indicator value and returns correlation
        results including match counts and affected entities.

        Args:
            indicators: List of indicators to correlate.

        Returns:
            List of IntelCorrelation results.
        """
        correlations: list[IntelCorrelation] = []

        for indicator in indicators:
            matches: list[dict[str, Any]] = []
            entities: list[str] = []

            if self._siem_client is not None:
                try:
                    siem_hits = await self._siem_client.search(
                        indicator.value,
                        indicator_type=indicator.indicator_type.value,
                    )
                    matches.extend(siem_hits.get("matches", []))
                    entities.extend(siem_hits.get("entities", []))
                except Exception as e:
                    logger.error(
                        "siem_correlation_failed",
                        indicator=indicator.value,
                        error=str(e),
                    )

            # Calculate risk score based on matches and confidence
            risk_score = self._calculate_risk_score(
                match_count=len(matches),
                confidence=indicator.confidence,
                has_mitre=bool(indicator.mitre_tactics),
            )

            correlations.append(
                IntelCorrelation(
                    indicator_value=indicator.value,
                    internal_matches=matches,
                    match_count=len(matches),
                    risk_score=risk_score,
                    entities_affected=list(set(entities)),
                )
            )

        logger.info(
            "intel_correlation_complete",
            indicators_checked=len(indicators),
            total_matches=sum(c.match_count for c in correlations),
        )
        return correlations

    async def assess_relevance(
        self,
        indicator: ThreatIndicator,
        correlation: IntelCorrelation,
    ) -> ThreatAssessment:
        """Score relevance of an indicator to the environment.

        Combines the indicator's confidence, correlation match data, and
        MITRE tactic coverage to produce an actionability assessment.

        Args:
            indicator: The threat indicator to assess.
            correlation: The correlation result for this indicator.

        Returns:
            A ThreatAssessment with relevance score and recommended actions.
        """
        # Base relevance from confidence level
        confidence_weights = {
            ThreatConfidence.CONFIRMED: 0.9,
            ThreatConfidence.PROBABLE: 0.7,
            ThreatConfidence.POSSIBLE: 0.4,
            ThreatConfidence.UNVERIFIED: 0.1,
        }
        base_score = confidence_weights.get(indicator.confidence, 0.1)

        # Boost for internal matches
        match_boost = min(correlation.match_count * 0.1, 0.3)

        # Boost for MITRE tactic coverage
        mitre_boost = 0.1 if indicator.mitre_tactics else 0.0

        relevance_score = min(base_score + match_boost + mitre_boost, 1.0)
        actionable = relevance_score >= 0.5

        actions: list[str] = []
        if actionable:
            actions.append(f"block_{indicator.indicator_type.value}")
            if correlation.match_count > 0:
                actions.append("investigate_matches")
            if indicator.mitre_tactics:
                actions.append("update_detection_rules")

        # TTL based on confidence — confirmed threats get longer TTL
        ttl_map = {
            ThreatConfidence.CONFIRMED: 168,  # 7 days
            ThreatConfidence.PROBABLE: 72,  # 3 days
            ThreatConfidence.POSSIBLE: 24,  # 1 day
            ThreatConfidence.UNVERIFIED: 6,  # 6 hours
        }

        return ThreatAssessment(
            indicator_value=indicator.value,
            relevance_score=relevance_score,
            actionable=actionable,
            recommended_actions=actions,
            ttl_hours=ttl_map.get(indicator.confidence, 24),
        )

    async def generate_ioc_report(
        self,
        assessments: list[ThreatAssessment],
    ) -> dict[str, Any]:
        """Generate an actionable IOC report from assessments.

        Args:
            assessments: List of threat assessments to include.

        Returns:
            Dictionary containing the IOC report.
        """
        actionable = [a for a in assessments if a.actionable]
        high_priority = [a for a in actionable if a.relevance_score >= 0.8]

        all_actions: list[str] = []
        for assessment in actionable:
            all_actions.extend(assessment.recommended_actions)

        report: dict[str, Any] = {
            "generated_at": datetime.now(UTC).isoformat(),
            "total_indicators": len(assessments),
            "actionable_count": len(actionable),
            "high_priority_count": len(high_priority),
            "indicators": [
                {
                    "value": a.indicator_value,
                    "relevance": a.relevance_score,
                    "actionable": a.actionable,
                    "actions": a.recommended_actions,
                    "ttl_hours": a.ttl_hours,
                }
                for a in sorted(assessments, key=lambda x: x.relevance_score, reverse=True)
            ],
            "recommended_actions": list(set(all_actions)),
        }

        logger.info(
            "ioc_report_generated",
            total=len(assessments),
            actionable=len(actionable),
            high_priority=len(high_priority),
        )
        return report

    async def distribute_intel(
        self,
        report: dict[str, Any],
        channels: list[str],
    ) -> dict[str, Any]:
        """Push threat intelligence to SIEM, firewall, EDR, and notification channels.

        Args:
            report: The IOC report to distribute.
            channels: Target channels (e.g., ["siem", "firewall", "edr", "slack"]).

        Returns:
            Dictionary with distribution results per channel.
        """
        results: dict[str, Any] = {}

        channel_clients = {
            "siem": self._siem_client,
            "firewall": self._firewall_client,
            "edr": self._edr_client,
            "notification": self._notification_client,
        }

        for channel in channels:
            client = channel_clients.get(channel)
            if client is None:
                results[channel] = {
                    "status": "skipped",
                    "reason": "client_not_configured",
                }
                continue

            try:
                resp = await client.ingest_indicators(report["indicators"])
                results[channel] = {
                    "status": "success",
                    "indicators_pushed": len(report["indicators"]),
                    "response": resp,
                }
            except Exception as e:
                logger.error(
                    "intel_distribution_failed",
                    channel=channel,
                    error=str(e),
                )
                results[channel] = {
                    "status": "error",
                    "error": str(e),
                }

        logger.info(
            "intel_distribution_complete",
            channels=channels,
            results_summary={ch: r.get("status") for ch, r in results.items()},
        )
        return results

    # --- Private helpers ---

    @staticmethod
    def _calculate_risk_score(
        match_count: int,
        confidence: ThreatConfidence,
        has_mitre: bool,
    ) -> float:
        """Calculate a 0-10 risk score for a correlated indicator."""
        confidence_base = {
            ThreatConfidence.CONFIRMED: 7.0,
            ThreatConfidence.PROBABLE: 5.0,
            ThreatConfidence.POSSIBLE: 3.0,
            ThreatConfidence.UNVERIFIED: 1.0,
        }
        score = confidence_base.get(confidence, 1.0)
        score += min(match_count * 0.5, 2.0)
        if has_mitre:
            score += 1.0
        return min(score, 10.0)
