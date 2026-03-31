"""Event Stream Processor Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any
from uuid import uuid4

import structlog

from .models import (
    CorrelationRule,
    CorrelationSeverity,
    EnrichedEvent,
    EventFormat,
    ParsedEvent,
    RouteDecision,
    StreamConnection,
)

logger = structlog.get_logger()

_SAMPLE_TOPICS: list[dict[str, Any]] = [
    {
        "topic": "security.events.endpoint",
        "broker": "kafka-broker-1:9092",
        "partition": 0,
        "format": EventFormat.CEF,
        "lag": 142,
    },
    {
        "topic": "security.events.network",
        "broker": "kafka-broker-1:9092",
        "partition": 1,
        "format": EventFormat.LEEF,
        "lag": 87,
    },
    {
        "topic": "security.events.cloud",
        "broker": "kafka-broker-2:9092",
        "partition": 0,
        "format": EventFormat.JSON,
        "lag": 33,
    },
    {
        "topic": "security.events.identity",
        "broker": "kafka-broker-2:9092",
        "partition": 1,
        "format": EventFormat.OCSF,
        "lag": 201,
    },
]

_SAMPLE_RAW_EVENTS: list[dict[str, Any]] = [
    {
        "event_type": "process_create",
        "source_ip": "10.10.1.55",
        "destination_ip": "185.220.101.10",
        "severity": "high",
        "raw_message": "CEF:0|CrowdStrike|Falcon|6.0|ProcessCreate|Process Created|8|...",
        "format": EventFormat.CEF,
    },
    {
        "event_type": "lateral_movement",
        "source_ip": "10.10.1.55",
        "destination_ip": "10.10.2.20",
        "severity": "critical",
        "raw_message": "LEEF:1.0|IBM|QRadar|7.3|lateral_move|...",
        "format": EventFormat.LEEF,
    },
    {
        "event_type": "privileged_login",
        "source_ip": "203.0.113.77",
        "destination_ip": "10.0.0.10",
        "severity": "high",
        "raw_message": '{"eventType":"privileged_login","actor":"svc-deploy","ts":"..."}',
        "format": EventFormat.JSON,
    },
    {
        "event_type": "data_exfiltration",
        "source_ip": "10.10.3.99",
        "destination_ip": "198.51.100.50",
        "severity": "critical",
        "raw_message": '{"class_uid":3002,"category_uid":3,"activity_id":2}',
        "format": EventFormat.OCSF,
    },
    {
        "event_type": "port_scan",
        "source_ip": "172.16.5.22",
        "destination_ip": "10.0.0.0/24",
        "severity": "medium",
        "raw_message": "syslog: port_scan detected from 172.16.5.22",
        "format": EventFormat.SYSLOG,
    },
    {
        "event_type": "malware_detected",
        "source_ip": "10.10.4.12",
        "destination_ip": "10.10.4.12",
        "severity": "critical",
        "raw_message": "CEF:0|Defender|ATP|8|Malware|Trojan.GenericKDZ|10|...",
        "format": EventFormat.CEF,
    },
]

_THREAT_INTEL: dict[str, dict[str, str]] = {
    "185.220.101.10": {"ioc_type": "ip", "tags": "tor_exit_node,c2"},
    "198.51.100.50": {"ioc_type": "ip", "tags": "data_theft,apt"},
    "203.0.113.77": {"ioc_type": "ip", "tags": "brute_force,credential_stuffing"},
}

_GEO_MAP: dict[str, tuple[str, str]] = {
    "185.220.101.10": ("DE", "AS12345 TOR"),
    "198.51.100.50": ("RU", "AS99999 APT-hosting"),
    "203.0.113.77": ("CN", "AS88888 Commercial"),
    "172.16.5.22": ("US", "AS64500 Internal"),
    "10.10.1.55": ("US", "AS64500 Corporate"),
    "10.10.3.99": ("US", "AS64500 Corporate"),
    "10.10.4.12": ("US", "AS64500 Corporate"),
}

_CORRELATION_RULES: list[dict[str, Any]] = [
    {
        "rule_name": "LateralMovement_AfterProcessCreate",
        "description": "Lateral movement observed within 5 min of process creation",
        "event_types": {"process_create", "lateral_movement"},
        "severity": CorrelationSeverity.CRITICAL,
        "confidence": 0.91,
        "mitre_technique": "T1021",
    },
    {
        "rule_name": "PrivilegedLogin_ExternalSource",
        "description": "Privileged account login from external IP",
        "event_types": {"privileged_login"},
        "severity": CorrelationSeverity.HIGH,
        "confidence": 0.85,
        "mitre_technique": "T1078",
    },
    {
        "rule_name": "DataExfil_KnownC2",
        "description": "Data transfer to known C2 / threat-intel IOC",
        "event_types": {"data_exfiltration"},
        "severity": CorrelationSeverity.CRITICAL,
        "confidence": 0.93,
        "mitre_technique": "T1041",
    },
    {
        "rule_name": "MalwareExecution_Endpoint",
        "description": "Malware execution confirmed on endpoint",
        "event_types": {"malware_detected"},
        "severity": CorrelationSeverity.CRITICAL,
        "confidence": 0.96,
        "mitre_technique": "T1204",
    },
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class EventStreamProcessorToolkit:
    """Tools for real-time security event stream processing."""

    def __init__(
        self,
        kafka_client: Any | None = None,
        threat_intel_api: Any | None = None,
        siem_client: Any | None = None,
    ) -> None:
        self._kafka_client = kafka_client
        self._threat_intel_api = threat_intel_api
        self._siem_client = siem_client

    async def connect_streams(
        self,
        tenant_id: str,
    ) -> list[StreamConnection]:
        """Connect to Kafka topics and return active stream connections."""
        logger.info(
            "esp.connect_streams",
            tenant_id=tenant_id,
        )

        if self._kafka_client is not None:
            try:
                raw = await self._kafka_client.list_topics(
                    tenant_id=tenant_id,
                )
                return [StreamConnection(**r) for r in raw]
            except Exception:
                logger.exception("esp.connect_streams.error")

        connections: list[StreamConnection] = []
        for i, topic_cfg in enumerate(_SAMPLE_TOPICS):
            connections.append(
                StreamConnection(
                    id=_gen_id("SC", tenant_id, i),
                    topic=topic_cfg["topic"],
                    broker=topic_cfg["broker"],
                    partition=topic_cfg["partition"],
                    offset=random.randint(10_000, 50_000),  # noqa: S311
                    consumer_group=f"shieldops-esp-{tenant_id}",
                    format=topic_cfg["format"],
                    connected=True,
                    lag=topic_cfg["lag"],
                )
            )
        return connections

    async def parse_events(
        self,
        connections: list[StreamConnection],
    ) -> list[ParsedEvent]:
        """Parse raw event records from connected streams."""
        logger.info(
            "esp.parse_events",
            stream_count=len(connections),
        )

        events: list[ParsedEvent] = []
        conn_ids = [c.id for c in connections]
        for i, raw in enumerate(_SAMPLE_RAW_EVENTS):
            stream_id = conn_ids[i % len(conn_ids)] if conn_ids else str(uuid4())
            noise = random.randint(0, 9)  # noqa: S311
            events.append(
                ParsedEvent(
                    id=_gen_id("PE", stream_id, i),
                    stream_id=stream_id,
                    timestamp=f"2026-03-30T10:{i:02d}:{noise:02d}Z",
                    format=raw["format"],
                    severity=raw["severity"],
                    source_ip=raw["source_ip"],
                    destination_ip=raw["destination_ip"],
                    event_type=raw["event_type"],
                    raw_message=raw["raw_message"],
                    fields={
                        "original_format": raw["format"],
                        "index": i,
                    },
                )
            )
        return events

    async def enrich_events(
        self,
        events: list[ParsedEvent],
    ) -> list[EnrichedEvent]:
        """Enrich parsed events with threat intel and geo data."""
        logger.info(
            "esp.enrich_events",
            event_count=len(events),
        )

        enriched: list[EnrichedEvent] = []
        for i, ev in enumerate(events):
            intel = _THREAT_INTEL.get(ev.destination_ip) or _THREAT_INTEL.get(ev.source_ip)
            geo = _GEO_MAP.get(ev.destination_ip) or _GEO_MAP.get(ev.source_ip, ("US", "AS64500"))
            ioc_match = intel is not None
            risk_score = 0.0
            if ioc_match:
                risk_score = 0.85 + round(random.uniform(0.0, 0.14), 2)  # noqa: S311
            elif ev.severity in ("critical", "high"):
                risk_score = round(random.uniform(0.5, 0.79), 2)  # noqa: S311
            else:
                risk_score = round(random.uniform(0.1, 0.49), 2)  # noqa: S311

            hostname = f"host-{ev.source_ip.replace('.', '-')}"
            enriched.append(
                EnrichedEvent(
                    id=_gen_id("EE", ev.id, i),
                    event_id=ev.id,
                    hostname=hostname,
                    geo_country=geo[0],
                    asn=geo[1],
                    threat_intel_match=ioc_match,
                    ioc_type=intel["ioc_type"] if intel else "",
                    ioc_value=ev.destination_ip if intel else "",
                    risk_score=risk_score,
                    tags=intel["tags"].split(",") if intel else [],
                )
            )
        return enriched

    async def correlate_events(
        self,
        events: list[ParsedEvent],
        enriched: list[EnrichedEvent],
    ) -> list[CorrelationRule]:
        """Apply correlation rules across parsed and enriched events."""
        logger.info(
            "esp.correlate_events",
            parsed=len(events),
            enriched=len(enriched),
        )

        event_type_map: dict[str, list[str]] = {}
        for ev in events:
            event_type_map.setdefault(ev.event_type, []).append(ev.id)

        fired: list[CorrelationRule] = []
        for i, rule_def in enumerate(_CORRELATION_RULES):
            matched: list[str] = []
            for et in rule_def["event_types"]:
                matched.extend(event_type_map.get(et, []))
            if not matched:
                continue
            fired.append(
                CorrelationRule(
                    id=_gen_id("CR", rule_def["rule_name"], i),
                    rule_name=rule_def["rule_name"],
                    description=rule_def["description"],
                    matched_event_ids=matched,
                    severity=rule_def["severity"],
                    confidence=rule_def["confidence"],
                    mitre_technique=rule_def["mitre_technique"],
                    fired_at="2026-03-30T10:10:00Z",
                )
            )
        return fired

    async def route_events(
        self,
        correlations: list[CorrelationRule],
    ) -> list[RouteDecision]:
        """Route correlated alerts to SIEM, SOAR, or ticketing systems."""
        logger.info(
            "esp.route_events",
            correlation_count=len(correlations),
        )

        decisions: list[RouteDecision] = []
        for i, rule in enumerate(correlations):
            is_critical = rule.severity in (
                CorrelationSeverity.CRITICAL,
                CorrelationSeverity.HIGH,
            )
            destination = "splunk-siem" if is_critical else "elastic-siem"
            playbook = f"PB-{rule.mitre_technique}-response" if is_critical else "PB-generic-triage"
            decisions.append(
                RouteDecision(
                    id=_gen_id("RD", rule.id, i),
                    correlation_id=rule.id,
                    destination=destination,
                    priority=1 if is_critical else 3,
                    playbook=playbook,
                    siem_forwarded=True,
                    soar_triggered=is_critical,
                    ticket_created=is_critical,
                )
            )
        return decisions

    async def record_metric(
        self,
        tenant_id: str,
        events_processed: int,
        correlations_fired: int,
        routes_created: int,
    ) -> None:
        """Record pipeline throughput metrics."""
        logger.info(
            "esp.record_metric",
            tenant_id=tenant_id,
            events_processed=events_processed,
            correlations_fired=correlations_fired,
            routes_created=routes_created,
        )
