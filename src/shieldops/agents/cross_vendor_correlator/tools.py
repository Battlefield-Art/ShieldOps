"""Tool functions for the Cross-Vendor Correlator Agent."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.cross_vendor_correlator.models import (
    CorrelationConfidence,
    EntityCorrelation,
    KillChainMapping,
    OCSFEvent,
    Situation,
    VendorAlert,
)

logger = structlog.get_logger()


class CrossVendorCorrelatorToolkit:
    """Toolkit for cross-vendor alert correlation."""

    def __init__(
        self,
        vendor_connectors: Any | None = None,
        ocsf_normalizer: Any | None = None,
        correlation_engine: Any | None = None,
        kill_chain_mapper: Any | None = None,
        situation_store: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._vendor_connectors = vendor_connectors
        self._ocsf_normalizer = ocsf_normalizer
        self._correlation_engine = correlation_engine
        self._kill_chain_mapper = kill_chain_mapper
        self._situation_store = situation_store
        self._policy_engine = policy_engine
        self._repository = repository

    async def ingest_from_vendor(
        self,
        tenant_id: str,
        vendors: list[str],
        time_window_minutes: int = 60,
    ) -> list[VendorAlert]:
        """Ingest alerts from specified vendors."""
        logger.info(
            "cross_vendor.ingest",
            tenant_id=tenant_id,
            vendors=vendors,
            window=time_window_minutes,
        )
        if self._vendor_connectors is not None:
            try:
                return await self._vendor_connectors.ingest(
                    tenant_id,
                    vendors,
                    time_window_minutes,
                )
            except Exception:
                logger.warning("cross_vendor.ingest_fallback")
        return []

    async def normalize_to_ocsf(
        self,
        alerts: list[VendorAlert],
    ) -> list[OCSFEvent]:
        """Normalize vendor alerts to OCSF schema."""
        logger.info(
            "cross_vendor.normalize",
            count=len(alerts),
        )
        events: list[OCSFEvent] = []
        sev_map = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }
        for alert in alerts:
            events.append(
                OCSFEvent(
                    id=alert.id or uuid4().hex[:12],
                    severity_id=sev_map.get(alert.severity.lower(), 0),
                    time=alert.timestamp,
                    message=alert.title,
                    observables=alert.entities,
                    vendor_name=alert.vendor,
                    product_name=alert.alert_type,
                    raw_data=alert.raw_data,
                )
            )
        return events

    async def correlate_by_entity(
        self,
        events: list[OCSFEvent],
    ) -> list[EntityCorrelation]:
        """Correlate OCSF events by shared entities."""
        logger.info(
            "cross_vendor.correlate",
            count=len(events),
        )
        if not events:
            return []

        entity_map: dict[str, list[OCSFEvent]] = {}
        for event in events:
            for obs in event.observables:
                key = obs.lower().strip()
                entity_map.setdefault(key, []).append(event)

        correlations: list[EntityCorrelation] = []
        for entity, group in entity_map.items():
            if len(group) < 2:
                continue
            vendors = list({e.vendor_name for e in group})
            vendor_ct = len(vendors)
            if vendor_ct >= 3:
                conf = CorrelationConfidence.STRONG
            elif vendor_ct >= 2:
                conf = CorrelationConfidence.MODERATE
            else:
                conf = CorrelationConfidence.WEAK
            times = [e.time for e in group if e.time]
            span = max(times) - min(times) if times else 0
            correlations.append(
                EntityCorrelation(
                    id=f"ec-{uuid4().hex[:8]}",
                    entity=entity,
                    entity_type="observable",
                    event_ids=[e.id for e in group],
                    vendors_involved=vendors,
                    confidence=conf,
                    time_span_seconds=span,
                )
            )
        return correlations

    async def map_kill_chain(
        self,
        correlations: list[EntityCorrelation],
        events: list[OCSFEvent],
    ) -> list[KillChainMapping]:
        """Map correlated events to kill chain stages."""
        logger.info(
            "cross_vendor.kill_chain",
            count=len(correlations),
        )
        event_map = {e.id: e for e in events}
        sev_tactic = {
            5: ("Impact", "T1499", "Endpoint DoS"),
            4: (
                "Lateral Movement",
                "T1021",
                "Remote Services",
            ),
            3: (
                "Execution",
                "T1059",
                "Command Scripting",
            ),
            2: (
                "Reconnaissance",
                "T1595",
                "Active Scanning",
            ),
        }
        mappings: list[KillChainMapping] = []
        for corr in correlations:
            evts = [event_map[eid] for eid in corr.event_ids if eid in event_map]
            max_sev = max(
                (e.severity_id for e in evts),
                default=0,
            )
            tactic, tid, tname = sev_tactic.get(
                max_sev,
                (
                    "Unknown",
                    "T0000",
                    "Unknown",
                ),
            )
            score = min(max_sev / 5.0, 1.0)
            mappings.append(
                KillChainMapping(
                    id=f"kc-{uuid4().hex[:8]}",
                    correlation_id=corr.id,
                    tactic=tactic,
                    technique_id=tid,
                    technique_name=tname,
                    events_mapped=corr.event_ids,
                    progression_score=score,
                )
            )
        return mappings

    async def create_situation(
        self,
        correlations: list[EntityCorrelation],
        kill_chain_mappings: list[KillChainMapping],
    ) -> list[Situation]:
        """Create unified situations from correlations."""
        logger.info(
            "cross_vendor.create_situations",
            correlations=len(correlations),
            mappings=len(kill_chain_mappings),
        )
        kc_map = {m.correlation_id: m for m in kill_chain_mappings}
        situations: list[Situation] = []
        for corr in correlations:
            if corr.confidence == (CorrelationConfidence.NONE):
                continue
            kc = kc_map.get(corr.id)
            stages = [kc.tactic] if kc else ["Unknown"]
            sev = "medium"
            if corr.confidence == (CorrelationConfidence.STRONG):
                sev = "critical"
            elif corr.confidence == (CorrelationConfidence.MODERATE):
                sev = "high"
            situations.append(
                Situation(
                    id=f"sit-{uuid4().hex[:8]}",
                    title=(f"Cross-vendor alert on {corr.entity}"),
                    narrative=(
                        f"{len(corr.vendors_involved)} vendors detected activity on {corr.entity}"
                    ),
                    severity=sev,
                    kill_chain_stages=stages,
                    correlation_ids=[corr.id],
                    vendor_count=len(corr.vendors_involved),
                    event_count=len(corr.event_ids),
                    recommended_actions=["Investigate entity activity"],
                    confidence=corr.confidence,
                )
            )
        return situations
