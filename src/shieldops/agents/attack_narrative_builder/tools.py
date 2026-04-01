"""Tool functions for the Attack Narrative Builder Agent."""

from __future__ import annotations

import random  # noqa: S311
from typing import Any
from uuid import uuid4

import structlog

logger = structlog.get_logger()

_SAMPLE_EVENTS: list[dict[str, Any]] = [
    {
        "source": "edr",
        "event_type": "process_creation",
        "severity": "medium",
        "host": "WORKSTATION-14",
        "user": "jdoe",
        "action": "powershell launched with encoded command",
        "outcome": "success",
    },
    {
        "source": "email_gateway",
        "event_type": "phishing_detected",
        "severity": "high",
        "host": "EXCHANGE-01",
        "user": "jdoe",
        "action": "phishing email with malicious attachment opened",
        "outcome": "delivered",
    },
    {
        "source": "edr",
        "event_type": "file_write",
        "severity": "high",
        "host": "WORKSTATION-14",
        "user": "jdoe",
        "action": "suspicious DLL dropped to AppData temp",
        "outcome": "success",
    },
    {
        "source": "siem",
        "event_type": "auth_success",
        "severity": "medium",
        "host": "DC-01",
        "user": "jdoe",
        "action": "kerberos TGT requested with forged ticket",
        "outcome": "success",
    },
    {
        "source": "ndr",
        "event_type": "lateral_movement",
        "severity": "critical",
        "host": "FILESERVER-02",
        "user": "admin-svc",
        "action": "PsExec remote execution from WORKSTATION-14",
        "outcome": "success",
    },
    {
        "source": "dlp",
        "event_type": "data_access",
        "severity": "critical",
        "host": "FILESERVER-02",
        "user": "admin-svc",
        "action": "bulk archive of sensitive financial documents",
        "outcome": "success",
    },
    {
        "source": "proxy",
        "event_type": "exfiltration",
        "severity": "critical",
        "host": "WORKSTATION-14",
        "user": "jdoe",
        "action": "large upload to external cloud storage API",
        "outcome": "success",
    },
    {
        "source": "edr",
        "event_type": "scheduled_task",
        "severity": "high",
        "host": "WORKSTATION-14",
        "user": "SYSTEM",
        "action": "persistence via scheduled task at boot",
        "outcome": "success",
    },
]

_TECHNIQUE_MAP: dict[str, dict[str, str]] = {
    "phishing_detected": {
        "id": "T1566.001",
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "phase": "delivery",
    },
    "process_creation": {
        "id": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
        "phase": "exploitation",
    },
    "file_write": {
        "id": "T1055",
        "name": "Process Injection",
        "tactic": "Defense Evasion",
        "phase": "installation",
    },
    "auth_success": {
        "id": "T1558.001",
        "name": "Golden Ticket",
        "tactic": "Credential Access",
        "phase": "exploitation",
    },
    "lateral_movement": {
        "id": "T1570",
        "name": "Lateral Tool Transfer",
        "tactic": "Lateral Movement",
        "phase": "command_and_control",
    },
    "data_access": {
        "id": "T1560.001",
        "name": "Archive via Utility",
        "tactic": "Collection",
        "phase": "actions_on_objectives",
    },
    "exfiltration": {
        "id": "T1567.002",
        "name": "Exfil to Cloud Storage",
        "tactic": "Exfiltration",
        "phase": "actions_on_objectives",
    },
    "scheduled_task": {
        "id": "T1053.005",
        "name": "Scheduled Task",
        "tactic": "Persistence",
        "phase": "installation",
    },
}


class AttackNarrativeBuilderToolkit:
    """Toolkit for attack narrative reconstruction."""

    def __init__(
        self,
        siem_client: Any | None = None,
        mitre_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._siem_client = siem_client
        self._mitre_client = mitre_client
        self._repository = repository

    async def collect_events(
        self,
        config: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Collect security events from sources."""
        logger.info("anb.collect_events", config_keys=list(config.keys()))
        events: list[dict[str, Any]] = []
        for i, sample in enumerate(_SAMPLE_EVENTS):
            events.append(
                {
                    "id": f"evt-{uuid4().hex[:8]}",
                    "source": sample["source"],
                    "event_type": sample["event_type"],
                    "severity": sample["severity"],
                    "host": sample["host"],
                    "user": sample["user"],
                    "action": sample["action"],
                    "outcome": sample["outcome"],
                    "timestamp": f"2026-03-30T0{i + 1}:{random.randint(0, 59):02d}:00Z",  # noqa: S311
                    "ioc_indicators": [],
                    "raw_data": {},
                }
            )
        return events

    async def cluster_events(
        self,
        events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Cluster related events together."""
        logger.info("anb.cluster_events", event_count=len(events))
        clusters: list[dict[str, Any]] = []
        by_host: dict[str, list[dict[str, Any]]] = {}
        for evt in events:
            by_host.setdefault(evt.get("host", ""), []).append(evt)

        for host, host_events in by_host.items():
            event_ids = [e.get("id", "") for e in host_events]
            technique = _TECHNIQUE_MAP.get(host_events[0].get("event_type", ""), {})
            clusters.append(
                {
                    "id": f"cl-{uuid4().hex[:8]}",
                    "label": f"Activity on {host}",
                    "event_ids": event_ids,
                    "kill_chain_phase": technique.get("phase", ""),
                    "mitre_technique_id": technique.get("id", ""),
                    "mitre_technique_name": technique.get("name", ""),
                    "confidence": round(random.uniform(0.7, 0.95), 2),  # noqa: S311
                    "summary": f"{len(host_events)} events on {host}",
                }
            )
        return clusters

    async def build_timeline(
        self,
        events: list[dict[str, Any]],
        clusters: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Build chronological attack timeline."""
        logger.info("anb.build_timeline", events=len(events), clusters=len(clusters))
        sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))
        timeline: list[dict[str, Any]] = []
        for i, evt in enumerate(sorted_events):
            phase = _TECHNIQUE_MAP.get(evt.get("event_type", ""), {}).get("phase", "")
            timeline.append(
                {
                    "sequence": i,
                    "timestamp": evt.get("timestamp", ""),
                    "event_id": evt.get("id", ""),
                    "host": evt.get("host", ""),
                    "user": evt.get("user", ""),
                    "action": evt.get("action", ""),
                    "kill_chain_phase": phase,
                    "severity": evt.get("severity", ""),
                }
            )
        return timeline

    async def generate_narrative(
        self,
        timeline: list[dict[str, Any]],
        clusters: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Generate narrative segments from timeline and clusters."""
        logger.info(
            "anb.generate_narrative",
            timeline=len(timeline),
            clusters=len(clusters),
        )
        segments: list[dict[str, Any]] = []
        phases_seen: dict[str, list[dict[str, Any]]] = {}
        for entry in timeline:
            phase = entry.get("kill_chain_phase", "unknown")
            phases_seen.setdefault(phase, []).append(entry)

        for i, (phase, entries) in enumerate(phases_seen.items()):
            hosts = list({e.get("host", "") for e in entries})
            users = list({e.get("user", "") for e in entries})
            descriptions = [e.get("action", "") for e in entries]
            techniques: list[str] = []
            for _e in entries:
                for _etype, tech in _TECHNIQUE_MAP.items():
                    if tech.get("phase") == phase and tech["id"] not in techniques:
                        techniques.append(tech["id"])

            segments.append(
                {
                    "id": f"seg-{uuid4().hex[:8]}",
                    "sequence": i,
                    "title": f"Phase: {phase.replace('_', ' ').title()}",
                    "description": "; ".join(descriptions),
                    "kill_chain_phase": phase,
                    "mitre_technique_ids": techniques,
                    "affected_hosts": hosts,
                    "affected_users": users,
                    "event_count": len(entries),
                }
            )
        return segments

    async def map_mitre(
        self,
        clusters: list[dict[str, Any]],
        segments: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Map attack to MITRE ATT&CK techniques."""
        logger.info("anb.map_mitre", clusters=len(clusters), segments=len(segments))
        mappings: list[dict[str, Any]] = []
        seen_techniques: set[str] = set()
        for cluster in clusters:
            tech_id = cluster.get("mitre_technique_id", "")
            if tech_id and tech_id not in seen_techniques:
                seen_techniques.add(tech_id)
                mappings.append(
                    {
                        "technique_id": tech_id,
                        "technique_name": cluster.get("mitre_technique_name", ""),
                        "cluster_id": cluster.get("id", ""),
                        "kill_chain_phase": cluster.get("kill_chain_phase", ""),
                        "confidence": cluster.get("confidence", 0.0),
                    }
                )

        for tech_data in _TECHNIQUE_MAP.values():
            tid = tech_data["id"]
            if tid not in seen_techniques:
                seen_techniques.add(tid)
                mappings.append(
                    {
                        "technique_id": tid,
                        "technique_name": tech_data["name"],
                        "cluster_id": "",
                        "kill_chain_phase": tech_data.get("phase", ""),
                        "confidence": round(random.uniform(0.5, 0.9), 2),  # noqa: S311
                    }
                )
        return mappings

    async def record_metric(
        self,
        metric_type: str,
        value: float,
    ) -> None:
        """Record a narrative builder metric."""
        logger.info("anb.record_metric", metric_type=metric_type, value=value)
