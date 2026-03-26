"""Tool functions for the Autonomous SOC Agent."""

import statistics
from typing import Any
from uuid import uuid4

import structlog

logger = structlog.get_logger()


class AutonomousSOCToolkit:
    """Toolkit for autonomous SOC operations.

    Works with existing SIEM investments (Splunk, Elastic,
    Sentinel) -- no rip-and-replace required.
    """

    def __init__(
        self,
        splunk_client: Any | None = None,
        elastic_client: Any | None = None,
        sentinel_client: Any | None = None,
        threat_intel: Any | None = None,
        policy_engine: Any | None = None,
        soar_engine: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._splunk = splunk_client
        self._elastic = elastic_client
        self._sentinel = sentinel_client
        self._threat_intel = threat_intel
        self._policy_engine = policy_engine
        self._soar_engine = soar_engine
        self._metrics_store = metrics_store
        self._repository = repository

    # -- Event Ingestion --

    async def ingest_from_splunk(
        self,
        search_query: str = "",
        time_range_minutes: int = 60,
    ) -> list[dict[str, Any]]:
        """Pull events from Splunk via REST/HEC."""
        logger.info(
            "autonomous_soc.ingest_splunk",
            query=search_query[:80],
            time_range=time_range_minutes,
        )
        if self._splunk:
            return await self._splunk.search(
                query=search_query,
                time_range_minutes=time_range_minutes,
            )
        return []

    async def ingest_from_elastic(
        self,
        index_pattern: str = "security-*",
        time_range_minutes: int = 60,
    ) -> list[dict[str, Any]]:
        """Pull events from Elastic SIEM."""
        logger.info(
            "autonomous_soc.ingest_elastic",
            index=index_pattern,
            time_range=time_range_minutes,
        )
        if self._elastic:
            return await self._elastic.search(
                index=index_pattern,
                time_range_minutes=time_range_minutes,
            )
        return []

    async def ingest_from_sentinel(
        self,
        time_range_minutes: int = 60,
    ) -> list[dict[str, Any]]:
        """Pull events from Microsoft Sentinel via KQL."""
        logger.info(
            "autonomous_soc.ingest_sentinel",
            time_range=time_range_minutes,
        )
        if self._sentinel:
            return await self._sentinel.query_incidents(
                time_range_minutes=time_range_minutes,
            )
        return []

    async def normalize_siem_event(
        self,
        source_siem: str,
        raw_event: dict[str, Any],
    ) -> dict[str, Any]:
        """Normalize a raw SIEM event to common schema."""
        logger.info(
            "autonomous_soc.normalize",
            source=source_siem,
        )
        event_id = f"evt-{uuid4().hex[:12]}"

        if source_siem == "splunk":
            return {
                "event_id": event_id,
                "source_siem": "splunk",
                "original_id": raw_event.get(
                    "sid",
                    "",
                ),
                "event_type": raw_event.get(
                    "search_name",
                    "unknown",
                ),
                "severity": raw_event.get(
                    "urgency",
                    "medium",
                ).lower(),
                "timestamp": raw_event.get(
                    "_time",
                    "",
                ),
                "source_ip": raw_event.get(
                    "src_ip",
                    "",
                ),
                "destination_ip": raw_event.get(
                    "dest_ip",
                    "",
                ),
                "hostname": raw_event.get(
                    "host",
                    "",
                ),
                "user": raw_event.get("user", ""),
                "description": raw_event.get(
                    "search_name",
                    "",
                ),
                "mitre_technique": raw_event.get(
                    "mitre_technique_id",
                    "",
                ),
                "confidence": float(
                    raw_event.get("confidence", 0.5),
                ),
                "raw_data": raw_event,
            }
        elif source_siem == "elastic":
            return {
                "event_id": event_id,
                "source_siem": "elastic",
                "original_id": raw_event.get(
                    "_id",
                    "",
                ),
                "event_type": raw_event.get(
                    "rule.name",
                    "unknown",
                ),
                "severity": raw_event.get(
                    "event.severity_label",
                    "medium",
                ).lower(),
                "timestamp": raw_event.get(
                    "@timestamp",
                    "",
                ),
                "source_ip": raw_event.get(
                    "source.ip",
                    "",
                ),
                "destination_ip": raw_event.get(
                    "destination.ip",
                    "",
                ),
                "hostname": raw_event.get(
                    "host.name",
                    "",
                ),
                "user": raw_event.get(
                    "user.name",
                    "",
                ),
                "description": raw_event.get(
                    "message",
                    "",
                ),
                "mitre_technique": (
                    raw_event.get(
                        "threat.technique.id",
                        [""],
                    )[0]
                    if raw_event.get(
                        "threat.technique.id",
                    )
                    else ""
                ),
                "confidence": 0.7,
                "raw_data": raw_event,
            }
        elif source_siem == "sentinel":
            return {
                "event_id": event_id,
                "source_siem": "sentinel",
                "original_id": raw_event.get(
                    "IncidentNumber",
                    "",
                ),
                "event_type": raw_event.get(
                    "Title",
                    "unknown",
                ),
                "severity": raw_event.get(
                    "Severity",
                    "Medium",
                ).lower(),
                "timestamp": raw_event.get(
                    "CreatedTimeUtc",
                    "",
                ),
                "source_ip": raw_event.get(
                    "SourceIP",
                    "",
                ),
                "destination_ip": raw_event.get(
                    "DestinationIP",
                    "",
                ),
                "hostname": raw_event.get(
                    "HostName",
                    "",
                ),
                "user": raw_event.get(
                    "AccountName",
                    "",
                ),
                "description": raw_event.get(
                    "Description",
                    "",
                ),
                "mitre_technique": (
                    raw_event.get(
                        "Tactics",
                        [""],
                    )[0]
                    if raw_event.get("Tactics")
                    else ""
                ),
                "confidence": 0.75,
                "raw_data": raw_event,
            }
        else:
            return {
                "event_id": event_id,
                "source_siem": source_siem,
                "original_id": raw_event.get(
                    "id",
                    "",
                ),
                "event_type": raw_event.get(
                    "type",
                    "unknown",
                ),
                "severity": raw_event.get(
                    "severity",
                    "medium",
                ).lower(),
                "timestamp": raw_event.get(
                    "timestamp",
                    "",
                ),
                "description": raw_event.get(
                    "description",
                    "",
                ),
                "raw_data": raw_event,
            }

    # -- Statistical Anomaly Detection --

    def detect_statistical_anomalies(
        self,
        events: list[dict[str, Any]],
        z_threshold: float = 2.5,
    ) -> list[dict[str, Any]]:
        """Statistical anomaly detection on event batches.

        Uses z-score on event frequency per entity plus
        severity weighting.
        """
        logger.info(
            "autonomous_soc.stat_detect",
            event_count=len(events),
            z_threshold=z_threshold,
        )
        severity_weight = {
            "critical": 5.0,
            "high": 4.0,
            "medium": 3.0,
            "low": 2.0,
            "info": 1.0,
        }

        # Group events by entity
        entity_scores: dict[str, list[float]] = {}
        entity_events: dict[str, list[str]] = {}
        for evt in events:
            entities = []
            if evt.get("source_ip"):
                entities.append(
                    f"ip:{evt['source_ip']}",
                )
            if evt.get("hostname"):
                entities.append(
                    f"host:{evt['hostname']}",
                )
            if evt.get("user"):
                entities.append(
                    f"user:{evt['user']}",
                )
            weight = severity_weight.get(
                evt.get("severity", "medium"),
                3.0,
            )
            for entity in entities:
                entity_scores.setdefault(
                    entity,
                    [],
                ).append(weight)
                entity_events.setdefault(
                    entity,
                    [],
                ).append(
                    evt.get("event_id", ""),
                )

        # Calculate z-scores
        all_totals = [sum(scores) for scores in entity_scores.values()]
        if len(all_totals) < 2:
            return []

        mean_val = statistics.mean(all_totals)
        stdev_val = statistics.stdev(all_totals)
        if stdev_val == 0:
            return []

        anomalies: list[dict[str, Any]] = []
        for entity, scores in entity_scores.items():
            total = sum(scores)
            z_score = (total - mean_val) / stdev_val
            if z_score >= z_threshold:
                anomaly_id = f"anom-{uuid4().hex[:12]}"
                anomalies.append(
                    {
                        "anomaly_id": anomaly_id,
                        "event_ids": entity_events.get(
                            entity,
                            [],
                        ),
                        "anomaly_type": "statistical",
                        "description": (
                            f"Entity {entity} has z-score {z_score:.2f} (threshold {z_threshold})"
                        ),
                        "statistical_score": z_score,
                        "baseline_deviation": z_score,
                        "affected_entities": [entity],
                        "detection_method": "z_score",
                        "is_anomalous": True,
                    },
                )

        return anomalies

    # -- Incident Correlation --

    async def correlate_anomalies(
        self,
        anomalies: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Correlate anomalies into incidents by entity overlap."""
        logger.info(
            "autonomous_soc.correlate",
            anomaly_count=len(anomalies),
        )
        # Group by shared entities
        entity_map: dict[str, list[dict[str, Any]]] = {}
        for anom in anomalies:
            for entity in anom.get(
                "affected_entities",
                [],
            ):
                entity_map.setdefault(
                    entity,
                    [],
                ).append(anom)

        incidents: list[dict[str, Any]] = []
        seen_anomaly_ids: set[str] = set()

        for entity, group in entity_map.items():
            anom_ids = [a.get("anomaly_id", "") for a in group]
            # Skip if all already correlated
            new_ids = [a for a in anom_ids if a not in seen_anomaly_ids]
            if not new_ids:
                continue

            seen_anomaly_ids.update(anom_ids)
            all_event_ids: list[str] = []
            for a in group:
                all_event_ids.extend(
                    a.get("event_ids", []),
                )

            incident_id = f"inc-{uuid4().hex[:12]}"
            max_score = max(a.get("statistical_score", 0.0) for a in group)
            confidence = min(
                1.0,
                0.5 + 0.1 * len(group),
            )

            incidents.append(
                {
                    "incident_id": incident_id,
                    "anomaly_ids": anom_ids,
                    "event_ids": list(
                        set(all_event_ids),
                    ),
                    "title": (f"Correlated anomalies on {entity}"),
                    "description": (
                        f"{len(group)} anomalies affecting {entity}, max score {max_score:.2f}"
                    ),
                    "affected_assets": [entity],
                    "confidence": confidence,
                },
            )

        return incidents

    # -- Response Orchestration --

    async def execute_response_step(
        self,
        step: dict[str, str],
        incident_id: str,
    ) -> dict[str, Any]:
        """Execute a single response step."""
        logger.info(
            "autonomous_soc.execute_step",
            incident_id=incident_id,
            action=step.get("action", ""),
            target=step.get("target", ""),
        )
        # Check policy before execution
        if self._policy_engine:
            policy_result = await self._policy_engine.evaluate(
                action=step.get("action", ""),
                target=step.get("target", ""),
                context={"incident_id": incident_id},
            )
            if not policy_result.get(
                "allowed",
                True,
            ):
                return {
                    "status": "blocked",
                    "reason": policy_result.get(
                        "reason",
                        "policy_denied",
                    ),
                }

        # Execute via SOAR engine if available
        if self._soar_engine:
            return await self._soar_engine.execute(
                action=step.get("action", ""),
                target=step.get("target", ""),
                tool=step.get("tool", ""),
            )

        return {
            "status": "simulated",
            "action": step.get("action", ""),
            "target": step.get("target", ""),
        }

    # -- Metrics --

    async def record_soc_metric(
        self,
        metric_name: str,
        value: float,
        labels: dict[str, str] | None = None,
    ) -> None:
        """Record SOC operational metric."""
        logger.info(
            "autonomous_soc.metric",
            metric=metric_name,
            value=value,
        )
        if self._metrics_store:
            await self._metrics_store.record(
                metric_name,
                value,
                labels=labels or {},
            )

    async def enrich_with_threat_intel(
        self,
        indicators: list[str],
    ) -> dict[str, Any]:
        """Enrich indicators with threat intelligence."""
        logger.info(
            "autonomous_soc.threat_intel",
            indicator_count=len(indicators),
        )
        if self._threat_intel:
            return await self._threat_intel.enrich(
                indicators,
            )
        return {
            "ioc_matches": [],
            "threat_feeds": [],
            "reputation_scores": {},
        }
