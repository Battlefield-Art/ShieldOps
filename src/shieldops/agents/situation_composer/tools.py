"""Tool functions for the Situation Composer Agent."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.situation_composer.models import (
    AlertSeverity,
    CorrelationLink,
    DeduplicatedAlert,
    KillChainPhase,
    RawAlert,
    RecommendedAction,
    Situation,
    SituationNarrative,
    SituationStatus,
)

logger = structlog.get_logger()

# Severity ordering for comparisons
_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# Kill-chain phase ordering
_KILL_CHAIN_ORDER = [p.value for p in KillChainPhase]


class SituationComposerToolkit:
    """Toolkit bridging the Situation Composer to alert stores and enrichment sources."""

    def __init__(
        self,
        alert_store: Any | None = None,
        threat_intel: Any | None = None,
        asset_db: Any | None = None,
    ) -> None:
        self._alert_store = alert_store
        self._threat_intel = threat_intel
        self._asset_db = asset_db

    # ------------------------------------------------------------------
    # 1. Collect
    # ------------------------------------------------------------------

    async def collect_alerts(
        self,
        time_window_minutes: int = 60,
        vendors: list[str] | None = None,
    ) -> list[RawAlert]:
        """Collect recent alerts from all connected vendors."""
        logger.info(
            "situation_composer.collect_alerts",
            time_window_minutes=time_window_minutes,
            vendors=vendors,
        )
        if self._alert_store:
            raw = await self._alert_store.query(
                time_window_minutes=time_window_minutes,
                vendors=vendors,
            )
            return [RawAlert(**r) if isinstance(r, dict) else r for r in raw]
        return []

    # ------------------------------------------------------------------
    # 2. Deduplicate
    # ------------------------------------------------------------------

    async def deduplicate_alerts(
        self,
        alerts: list[RawAlert],
    ) -> list[DeduplicatedAlert]:
        """Merge duplicate/related alerts using field similarity matching."""
        logger.info(
            "situation_composer.deduplicate_alerts",
            alert_count=len(alerts),
        )
        # Group by (vendor, title, source_ip, hostname) as a dedup key
        groups: dict[str, list[RawAlert]] = {}
        for alert in alerts:
            key = f"{alert.vendor}|{alert.title}|{alert.source_ip}|{alert.hostname}"
            groups.setdefault(key, []).append(alert)

        deduped: list[DeduplicatedAlert] = []
        for _key, group in groups.items():
            canonical = group[0]
            vendors = sorted({a.vendor for a in group})
            timestamps = [a.timestamp for a in group if a.timestamp]
            merged_data: dict[str, Any] = {}
            for a in group:
                merged_data.update(a.raw_data)

            deduped.append(
                DeduplicatedAlert(
                    id=f"dedup-{uuid4().hex[:12]}",
                    canonical_alert_id=canonical.id,
                    duplicate_count=len(group),
                    vendors=vendors,
                    merged_data=merged_data,
                    first_seen=min(timestamps) if timestamps else "",
                    last_seen=max(timestamps) if timestamps else "",
                )
            )

        logger.info(
            "situation_composer.deduplicate_complete",
            input_count=len(alerts),
            output_count=len(deduped),
        )
        return deduped

    # ------------------------------------------------------------------
    # 3. Correlate
    # ------------------------------------------------------------------

    async def correlate_signals(
        self,
        alerts: list[RawAlert],
    ) -> list[CorrelationLink]:
        """Identify correlations across alerts by shared IPs, users, timeframes."""
        logger.info(
            "situation_composer.correlate_signals",
            alert_count=len(alerts),
        )
        entity_groups: dict[str, list[RawAlert]] = {}
        for alert in alerts:
            keys: list[str] = []
            if alert.source_ip:
                keys.append(f"src_ip:{alert.source_ip}")
            if alert.dest_ip:
                keys.append(f"dst_ip:{alert.dest_ip}")
            if alert.hostname:
                keys.append(f"host:{alert.hostname}")
            if alert.user:
                keys.append(f"user:{alert.user}")
            for key in keys:
                entity_groups.setdefault(key, []).append(alert)

        correlations: list[CorrelationLink] = []
        for entity_key, group in entity_groups.items():
            if len(group) < 2:
                continue

            alert_ids = [a.id for a in group]
            vendors = sorted({a.vendor for a in group})
            multi_vendor = len(vendors) >= 2

            # Confidence boosted by vendor diversity
            confidence = min(1.0, 0.5 + 0.15 * len(vendors))

            # Determine correlation type
            corr_type = "cross_vendor_entity" if multi_vendor else "single_vendor_entity"

            # Infer kill-chain phase from alert types / severity
            phase = self._infer_kill_chain_phase(group)

            correlations.append(
                CorrelationLink(
                    id=f"corr-{uuid4().hex[:12]}",
                    alert_ids=alert_ids,
                    correlation_type=corr_type,
                    confidence=confidence,
                    description=(
                        f"{len(group)} alerts for {entity_key} across {', '.join(vendors)}"
                    ),
                    kill_chain_phase=phase,
                )
            )

        logger.info(
            "situation_composer.correlate_complete",
            correlation_count=len(correlations),
        )
        return correlations

    # ------------------------------------------------------------------
    # 4. Build narrative
    # ------------------------------------------------------------------

    async def build_narrative(
        self,
        alerts: list[RawAlert],
        correlations: list[CorrelationLink],
    ) -> SituationNarrative:
        """Construct a kill-chain narrative from correlated alerts."""
        logger.info(
            "situation_composer.build_narrative",
            alert_count=len(alerts),
            correlation_count=len(correlations),
        )
        # Build kill-chain mapping
        kc_mapping: dict[str, list[str]] = {}
        for corr in correlations:
            if corr.kill_chain_phase:
                phase = corr.kill_chain_phase.value
                kc_mapping.setdefault(phase, []).extend(corr.alert_ids)

        # Build timeline from alerts
        timeline: list[dict[str, Any]] = []
        for alert in sorted(alerts, key=lambda a: a.timestamp or ""):
            timeline.append(
                {
                    "timestamp": alert.timestamp,
                    "event": alert.title,
                    "vendor": alert.vendor,
                    "severity": alert.severity.value if alert.severity else "",
                    "alert_id": alert.id,
                }
            )

        # Collect affected assets
        affected: set[str] = set()
        for alert in alerts:
            if alert.hostname:
                affected.add(alert.hostname)
            if alert.source_ip:
                affected.add(alert.source_ip)
            if alert.dest_ip:
                affected.add(alert.dest_ip)
            if alert.user:
                affected.add(alert.user)

        # Extract IOCs from raw data
        iocs: set[str] = set()
        for alert in alerts:
            if alert.source_ip:
                iocs.add(alert.source_ip)
            if alert.dest_ip:
                iocs.add(alert.dest_ip)
            for key in ("hash", "md5", "sha256", "domain", "url"):
                val = alert.raw_data.get(key, "")
                if val:
                    iocs.add(str(val))

        # Confidence based on correlation strength
        avg_conf = (
            sum(c.confidence for c in correlations) / len(correlations) if correlations else 0.0
        )

        # Determine highest severity for title
        max_sev = self._max_severity(alerts)

        narrative = SituationNarrative(
            id=f"narr-{uuid4().hex[:12]}",
            title=(
                f"{max_sev.value.upper()} situation across "
                f"{len({a.vendor for a in alerts})} vendors"
            ),
            executive_summary=(
                f"Composed situation with {len(alerts)} alerts from "
                f"{len({a.vendor for a in alerts})} vendor(s), "
                f"{len(correlations)} correlation links. "
                f"Kill chain phases covered: {', '.join(sorted(kc_mapping.keys()))}."
            ),
            kill_chain_mapping=kc_mapping,
            timeline=timeline,
            affected_assets=sorted(affected),
            ioc_list=sorted(iocs),
            mitre_techniques=[],
            confidence=avg_conf,
        )

        # Enrich IOCs via threat intel if available
        if self._threat_intel and iocs:
            try:
                enrichment = await self._threat_intel.enrich(list(iocs))
                if enrichment.get("mitre_techniques"):
                    narrative.mitre_techniques = enrichment["mitre_techniques"]
            except Exception:
                logger.debug("situation_composer.threat_intel_enrichment_failed")

        return narrative

    # ------------------------------------------------------------------
    # 5. Recommend actions
    # ------------------------------------------------------------------

    async def recommend_actions(
        self,
        narrative: SituationNarrative,
    ) -> list[RecommendedAction]:
        """Generate response recommendations based on situation severity and scope."""
        logger.info(
            "situation_composer.recommend_actions",
            narrative_id=narrative.id,
            affected_count=len(narrative.affected_assets),
        )
        actions: list[RecommendedAction] = []

        # Containment for each affected asset
        for asset in narrative.affected_assets[:10]:
            actions.append(
                RecommendedAction(
                    id=f"act-{uuid4().hex[:12]}",
                    action_type="contain",
                    target=asset,
                    description=f"Network-isolate {asset} to prevent lateral movement",
                    risk_level="medium",
                    auto_executable=narrative.confidence >= 0.85,
                    estimated_impact=f"Asset {asset} will be isolated from the network",
                )
            )

        # Investigation action
        actions.append(
            RecommendedAction(
                id=f"act-{uuid4().hex[:12]}",
                action_type="investigate",
                target="all_affected",
                description=("Deep investigation of correlated events across all vendors"),
                risk_level="low",
                auto_executable=False,
                estimated_impact="No operational impact — read-only investigation",
            )
        )

        # Block IOCs
        for ioc in narrative.ioc_list[:5]:
            actions.append(
                RecommendedAction(
                    id=f"act-{uuid4().hex[:12]}",
                    action_type="block",
                    target=ioc,
                    description=f"Block IOC {ioc} at network perimeter",
                    risk_level="low",
                    auto_executable=True,
                    estimated_impact=f"Traffic to/from {ioc} will be blocked",
                )
            )

        # Escalation if low confidence
        if narrative.confidence < 0.7:
            actions.append(
                RecommendedAction(
                    id=f"act-{uuid4().hex[:12]}",
                    action_type="escalate",
                    target="soc_lead",
                    description="Escalate to SOC lead — confidence below threshold",
                    risk_level="low",
                    auto_executable=True,
                    estimated_impact="SOC lead will be paged for manual review",
                )
            )

        return actions

    # ------------------------------------------------------------------
    # 6. Publish
    # ------------------------------------------------------------------

    async def publish_situation(
        self,
        narrative: SituationNarrative | None,
        actions: list[RecommendedAction],
    ) -> Situation:
        """Create and publish the composed situation."""
        sit_id = f"sit-{uuid4().hex[:12]}"
        logger.info(
            "situation_composer.publish_situation",
            situation_id=sit_id,
            has_narrative=narrative is not None,
            action_count=len(actions),
        )

        severity = AlertSeverity.MEDIUM
        if narrative and narrative.confidence >= 0.8:
            # Derive severity from narrative content
            kc_phases = list(narrative.kill_chain_mapping.keys())
            if any(
                p in kc_phases
                for p in [
                    KillChainPhase.COMMAND_AND_CONTROL.value,
                    KillChainPhase.ACTIONS_ON_OBJECTIVES.value,
                ]
            ):
                severity = AlertSeverity.CRITICAL
            elif any(
                p in kc_phases
                for p in [
                    KillChainPhase.EXPLOITATION.value,
                    KillChainPhase.INSTALLATION.value,
                ]
            ):
                severity = AlertSeverity.HIGH

        situation = Situation(
            id=sit_id,
            status=SituationStatus.ACTIVE if narrative else SituationStatus.DRAFT,
            severity=severity,
            narrative=narrative,
            alerts=[],
            correlations=[],
            recommended_actions=actions,
            created_at="",
            updated_at="",
        )

        if self._alert_store:
            try:
                await self._alert_store.save_situation(situation.model_dump())
            except Exception:
                logger.debug("situation_composer.save_situation_failed")

        return situation

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _infer_kill_chain_phase(
        alerts: list[RawAlert],
    ) -> KillChainPhase | None:
        """Heuristic kill-chain phase inference from alert types."""
        types_lower = {a.alert_type.lower() for a in alerts if a.alert_type}
        sevs = {a.severity for a in alerts}

        if types_lower & {"scan", "recon", "enumeration", "discovery"}:
            return KillChainPhase.RECONNAISSANCE
        if types_lower & {"phishing", "spearphish", "email", "delivery"}:
            return KillChainPhase.DELIVERY
        if types_lower & {"exploit", "cve", "vulnerability", "rce"}:
            return KillChainPhase.EXPLOITATION
        if types_lower & {"malware", "dropper", "persistence", "install"}:
            return KillChainPhase.INSTALLATION
        if types_lower & {"c2", "beacon", "callback", "command_and_control"}:
            return KillChainPhase.COMMAND_AND_CONTROL
        if types_lower & {"exfiltration", "data_theft", "lateral", "ransomware"}:
            return KillChainPhase.ACTIONS_ON_OBJECTIVES

        # Fall back to severity heuristic
        if AlertSeverity.CRITICAL in sevs:
            return KillChainPhase.ACTIONS_ON_OBJECTIVES
        if AlertSeverity.HIGH in sevs:
            return KillChainPhase.EXPLOITATION

        return None

    @staticmethod
    def _max_severity(alerts: list[RawAlert]) -> AlertSeverity:
        """Return the highest severity from a list of alerts."""
        if not alerts:
            return AlertSeverity.INFO
        return max(
            (a.severity for a in alerts),
            key=lambda s: _SEVERITY_ORDER.index(s.value) if s.value in _SEVERITY_ORDER else 0,
        )
