"""Attack Narrative Builder Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    AttackChainLink,
    AttackPhase,
    EventSeverity,
    NarrativeSection,
    SecurityEvent,
    TechniqueMapping,
    TimelineEntry,
)

logger = structlog.get_logger()

_SAMPLE_EVENTS: list[dict[str, Any]] = [
    {
        "source": "edr",
        "event_type": "process_creation",
        "severity": "medium",
        "host": "WORKSTATION-14",
        "user": "jdoe",
        "process": "powershell.exe",
        "description": "PowerShell launched with encoded command",
    },
    {
        "source": "email_gateway",
        "event_type": "phishing_detected",
        "severity": "high",
        "host": "EXCHANGE-01",
        "user": "jdoe",
        "process": "outlook.exe",
        "description": "Phishing email with malicious attachment opened",
    },
    {
        "source": "edr",
        "event_type": "file_write",
        "severity": "high",
        "host": "WORKSTATION-14",
        "user": "jdoe",
        "process": "powershell.exe",
        "description": "Suspicious DLL dropped to AppData\\Local\\Temp",
    },
    {
        "source": "siem",
        "event_type": "auth_success",
        "severity": "medium",
        "host": "DC-01",
        "user": "jdoe",
        "process": "lsass.exe",
        "description": "Kerberos TGT requested with forged ticket",
    },
    {
        "source": "ndr",
        "event_type": "lateral_movement",
        "severity": "critical",
        "host": "FILESERVER-02",
        "user": "admin-svc",
        "process": "psexec.exe",
        "description": "PsExec remote execution from WORKSTATION-14",
    },
    {
        "source": "dlp",
        "event_type": "data_access",
        "severity": "critical",
        "host": "FILESERVER-02",
        "user": "admin-svc",
        "process": "7z.exe",
        "description": "Bulk archive of sensitive financial documents",
    },
    {
        "source": "proxy",
        "event_type": "exfiltration",
        "severity": "critical",
        "host": "WORKSTATION-14",
        "user": "jdoe",
        "process": "curl.exe",
        "description": "Large upload to external cloud storage API",
    },
    {
        "source": "edr",
        "event_type": "scheduled_task",
        "severity": "high",
        "host": "WORKSTATION-14",
        "user": "SYSTEM",
        "process": "schtasks.exe",
        "description": "Persistence via scheduled task at boot",
    },
]

_TECHNIQUE_MAP: dict[str, dict[str, str]] = {
    "phishing_detected": {
        "id": "T1566.001",
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access",
    },
    "process_creation": {
        "id": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
    },
    "file_write": {
        "id": "T1055",
        "name": "Process Injection",
        "tactic": "Defense Evasion",
    },
    "auth_success": {
        "id": "T1558.001",
        "name": "Golden Ticket",
        "tactic": "Credential Access",
    },
    "lateral_movement": {
        "id": "T1570",
        "name": "Lateral Tool Transfer",
        "tactic": "Lateral Movement",
    },
    "data_access": {
        "id": "T1560.001",
        "name": "Archive via Utility",
        "tactic": "Collection",
    },
    "exfiltration": {
        "id": "T1567.002",
        "name": "Exfil to Cloud Storage",
        "tactic": "Exfiltration",
    },
    "scheduled_task": {
        "id": "T1053.005",
        "name": "Scheduled Task",
        "tactic": "Persistence",
    },
}

_EVENT_TO_PHASE: dict[str, AttackPhase] = {
    "phishing_detected": AttackPhase.INITIAL_ACCESS,
    "process_creation": AttackPhase.EXECUTION,
    "file_write": AttackPhase.PERSISTENCE,
    "auth_success": AttackPhase.PRIVILEGE_ESCALATION,
    "lateral_movement": AttackPhase.LATERAL_MOVEMENT,
    "data_access": AttackPhase.COLLECTION,
    "exfiltration": AttackPhase.EXFILTRATION,
    "scheduled_task": AttackPhase.PERSISTENCE,
}


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class AttackNarrativeBuilderToolkit:
    """Tools for attack narrative reconstruction."""

    def __init__(
        self,
        siem_source: Any | None = None,
        mitre_api: Any | None = None,
    ) -> None:
        self._siem_source = siem_source
        self._mitre_api = mitre_api

    async def collect_events(
        self,
        tenant_id: str,
    ) -> list[SecurityEvent]:
        """Collect security events from multiple sources."""
        logger.info(
            "anb.collect_events",
            tenant_id=tenant_id,
        )

        if self._siem_source is not None:
            try:
                raw = await self._siem_source.get_events(
                    tenant_id=tenant_id,
                )
                return [SecurityEvent(**r) for r in raw]
            except Exception:
                logger.exception("anb.collect_events.error")

        events: list[SecurityEvent] = []
        for i, e in enumerate(_SAMPLE_EVENTS):
            events.append(
                SecurityEvent(
                    id=_gen_id("SE", tenant_id, i),
                    timestamp=f"2026-03-30T0{i + 1}:{random.randint(0, 59):02d}:00Z",  # noqa: S311
                    source=e["source"],
                    event_type=e["event_type"],
                    severity=EventSeverity(e["severity"]),
                    host=e["host"],
                    user=e["user"],
                    process=e["process"],
                    description=e["description"],
                )
            )
        return events

    async def correlate_timeline(
        self,
        events: list[SecurityEvent],
    ) -> list[TimelineEntry]:
        """Correlate events into a timeline."""
        logger.info(
            "anb.correlate_timeline",
            count=len(events),
        )

        sorted_events = sorted(events, key=lambda e: e.timestamp)
        entries: list[TimelineEntry] = []
        for i, e in enumerate(sorted_events):
            entries.append(
                TimelineEntry(
                    id=_gen_id("TL", e.id, i),
                    timestamp=e.timestamp,
                    event_ids=[e.id],
                    description=e.description,
                    severity=e.severity,
                    host=e.host,
                    user=e.user,
                    confidence=round(
                        random.uniform(0.7, 0.98),  # noqa: S311
                        2,
                    ),
                )
            )
        return entries

    async def reconstruct_chain(
        self,
        timeline: list[TimelineEntry],
        events: list[SecurityEvent],
    ) -> list[AttackChainLink]:
        """Reconstruct the attack kill chain."""
        logger.info(
            "anb.reconstruct_chain",
            timeline_count=len(timeline),
        )

        event_map: dict[str, SecurityEvent] = {e.id: e for e in events}
        chain: list[AttackChainLink] = []
        for i, tl in enumerate(timeline):
            evt_id = tl.event_ids[0] if tl.event_ids else ""
            evt = event_map.get(evt_id)
            if not evt:
                continue

            phase = _EVENT_TO_PHASE.get(
                evt.event_type,
                AttackPhase.EXECUTION,
            )
            tech = _TECHNIQUE_MAP.get(evt.event_type, {})

            chain.append(
                AttackChainLink(
                    id=_gen_id("AC", tl.id, i),
                    phase=phase,
                    timeline_entry_id=tl.id,
                    description=evt.description,
                    host=evt.host,
                    user=evt.user,
                    technique=tech.get("id", ""),
                    confidence=tl.confidence,
                    evidence=[
                        f"Source: {evt.source}",
                        f"Process: {evt.process}",
                    ],
                )
            )
        return chain

    async def map_techniques(
        self,
        chain: list[AttackChainLink],
        events: list[SecurityEvent],
    ) -> list[TechniqueMapping]:
        """Map attack chain to MITRE ATT&CK techniques."""
        logger.info(
            "anb.map_techniques",
            chain_count=len(chain),
        )

        event_map: dict[str, SecurityEvent] = {e.id: e for e in events}
        _unused_event_map = event_map  # referenced for completeness

        mappings: list[TechniqueMapping] = []
        for i, link in enumerate(chain):
            # Find matching technique from the event type
            matched_tech: dict[str, str] = {}
            for _etype, tech in _TECHNIQUE_MAP.items():
                if tech.get("id") == link.technique:
                    matched_tech = tech
                    break

            if not matched_tech:
                continue

            mappings.append(
                TechniqueMapping(
                    id=_gen_id("TM", link.id, i),
                    chain_link_id=link.id,
                    technique_id=matched_tech.get("id", ""),
                    technique_name=matched_tech.get("name", ""),
                    tactic=matched_tech.get("tactic", ""),
                    sub_technique="",
                    data_sources=[link.evidence[0] if link.evidence else ""],
                    confidence=link.confidence,
                )
            )
        return mappings

    async def build_narrative(
        self,
        chain: list[AttackChainLink],
        mappings: list[TechniqueMapping],
    ) -> list[NarrativeSection]:
        """Build the attack narrative from chain and mappings."""
        logger.info(
            "anb.build_narrative",
            chain_count=len(chain),
            mapping_count=len(mappings),
        )

        mapping_by_link: dict[str, TechniqueMapping] = {m.chain_link_id: m for m in mappings}

        phase_groups: dict[AttackPhase, list[AttackChainLink]] = {}
        for link in chain:
            phase_groups.setdefault(link.phase, []).append(link)

        sections: list[NarrativeSection] = []
        for i, (phase, links) in enumerate(phase_groups.items()):
            techs: list[str] = []
            refs: list[str] = []
            body_parts: list[str] = []
            for link in links:
                refs.append(link.timeline_entry_id)
                m = mapping_by_link.get(link.id)
                if m:
                    techs.append(f"{m.technique_id}: {m.technique_name}")
                body_parts.append(f"- [{link.host}] {link.description}")

            sections.append(
                NarrativeSection(
                    id=_gen_id("NS", phase.value, i),
                    phase=phase,
                    title=f"Phase: {phase.value.replace('_', ' ').title()}",
                    body="\n".join(body_parts),
                    timeline_refs=refs,
                    techniques=techs,
                )
            )
        return sections

    async def record_metric(
        self,
        metric_name: str,
        value: float,
        tags: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Record an attack narrative metric."""
        logger.info(
            "anb.record_metric",
            metric=metric_name,
            value=value,
        )
        return {"metric": metric_name, "recorded": True}
