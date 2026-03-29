"""Physical Access Monitor Agent — Tool functions."""

from __future__ import annotations

import hashlib
import time
from typing import Any

import structlog

from .models import (
    AccessEvent,
    AccessType,
    AlertLevel,
    ZonePolicy,
)

logger = structlog.get_logger()

_SAMPLE_EVENTS: list[dict[str, Any]] = [
    {
        "person": "John Smith",
        "badge": "B-10042",
        "type": AccessType.BADGE_SWIPE,
        "zone": "data-center-A",
        "door": "DC-A-MAIN",
        "granted": True,
        "after_hours": True,
        "restricted": True,
    },
    {
        "person": "Jane Doe",
        "badge": "B-10078",
        "type": AccessType.TAILGATE,
        "zone": "server-room-B",
        "door": "SR-B-02",
        "granted": False,
        "after_hours": False,
        "restricted": True,
    },
    {
        "person": "Unknown Visitor",
        "badge": "V-TEMP-003",
        "type": AccessType.VISITOR_PASS,
        "zone": "data-center-A",
        "door": "DC-A-SIDE",
        "granted": True,
        "after_hours": False,
        "restricted": True,
    },
    {
        "person": "Mike Chen",
        "badge": "B-10055",
        "type": AccessType.BADGE_SWIPE,
        "zone": "lab-restricted",
        "door": "LAB-01",
        "granted": True,
        "after_hours": True,
        "restricted": True,
    },
    {
        "person": "Sarah Wilson",
        "badge": "B-10099",
        "type": AccessType.BIOMETRIC,
        "zone": "executive-floor",
        "door": "EXEC-MAIN",
        "granted": True,
        "after_hours": False,
        "restricted": False,
    },
    {
        "person": "Unknown",
        "badge": "B-CLONED-01",
        "type": AccessType.FORCED_ENTRY,
        "zone": "network-closet-3",
        "door": "NC-03",
        "granted": False,
        "after_hours": True,
        "restricted": True,
    },
]

_ZONE_POLICIES: dict[str, dict[str, Any]] = {
    "data-center-A": {
        "max_occupancy": 20,
        "escort": True,
        "start": "22:00",
        "end": "06:00",
        "roles": ["dc-admin", "infra-eng"],
        "mfa": True,
    },
    "server-room-B": {
        "max_occupancy": 10,
        "escort": True,
        "start": "20:00",
        "end": "07:00",
        "roles": ["sre", "dc-admin"],
        "mfa": True,
    },
    "lab-restricted": {
        "max_occupancy": 5,
        "escort": True,
        "start": "18:00",
        "end": "08:00",
        "roles": ["research-eng"],
        "mfa": True,
    },
    "network-closet-3": {
        "max_occupancy": 2,
        "escort": False,
        "start": "19:00",
        "end": "07:00",
        "roles": ["network-eng"],
        "mfa": False,
    },
}


class PhysicalAccessMonitorToolkit:
    """Tools for physical access monitoring and analysis."""

    def __init__(
        self,
        access_system: Any | None = None,
    ) -> None:
        self._access_system = access_system
        self._event_cache: list[AccessEvent] = []

    async def ingest_events(
        self,
        tenant_id: str,
        zones: list[str] | None = None,
        time_range_hours: int = 24,
    ) -> list[AccessEvent]:
        """Ingest access events from badge readers."""
        logger.info(
            "physical_access.ingest_events",
            tenant_id=tenant_id,
            zones=zones,
        )
        events: list[AccessEvent] = []
        now = time.time()

        for idx, evt in enumerate(_SAMPLE_EVENTS):
            if zones and evt["zone"] not in zones:
                continue
            ehash = hashlib.md5(  # noqa: S324  # nosec B324
                f"{evt['badge']}{idx}".encode(),
                usedforsecurity=False,
            ).hexdigest()[:8]
            events.append(
                AccessEvent(
                    event_id=f"evt-{ehash}",
                    person_id=f"pid-{ehash[:6]}",
                    person_name=evt["person"],
                    badge_id=evt["badge"],
                    access_type=evt["type"],
                    zone=evt["zone"],
                    door_id=evt["door"],
                    timestamp=now - (idx * 600),
                    granted=evt["granted"],
                    after_hours=evt["after_hours"],
                    restricted_area=evt["restricted"],
                )
            )

        self._event_cache = events
        return events

    async def analyze_patterns(
        self,
        events: list[AccessEvent],
    ) -> list[dict[str, Any]]:
        """Analyze access patterns for anomalies."""
        logger.info(
            "physical_access.analyze_patterns",
            event_count=len(events),
        )
        patterns: list[dict[str, Any]] = []

        tailgates = [e for e in events if e.access_type == AccessType.TAILGATE]
        if tailgates:
            patterns.append(
                {
                    "type": "tailgating",
                    "count": len(tailgates),
                    "zones": list({e.zone for e in tailgates}),
                    "severity": AlertLevel.HIGH,
                }
            )

        after_hours = [e for e in events if e.after_hours]
        if after_hours:
            patterns.append(
                {
                    "type": "after_hours_access",
                    "count": len(after_hours),
                    "persons": [e.person_name for e in after_hours],
                    "severity": AlertLevel.MEDIUM,
                }
            )

        forced = [e for e in events if e.access_type == AccessType.FORCED_ENTRY]
        if forced:
            patterns.append(
                {
                    "type": "forced_entry_attempt",
                    "count": len(forced),
                    "zones": list({e.zone for e in forced}),
                    "severity": AlertLevel.CRITICAL,
                }
            )

        visitor_restricted = [
            e for e in events if e.access_type == AccessType.VISITOR_PASS and e.restricted_area
        ]
        if visitor_restricted:
            patterns.append(
                {
                    "type": "visitor_in_restricted",
                    "count": len(visitor_restricted),
                    "zones": list({e.zone for e in visitor_restricted}),
                    "severity": AlertLevel.HIGH,
                }
            )

        return patterns

    async def detect_anomalies(
        self,
        events: list[AccessEvent],
        patterns: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Detect anomalies from access patterns."""
        logger.info(
            "physical_access.detect_anomalies",
            pattern_count=len(patterns),
        )
        anomalies: list[dict[str, Any]] = []

        for pat in patterns:
            sev = pat.get("severity", AlertLevel.LOW)
            if sev in (
                AlertLevel.CRITICAL,
                AlertLevel.HIGH,
            ):
                anomalies.append(
                    {
                        "anomaly_type": pat["type"],
                        "alert_level": sev,
                        "details": pat,
                        "requires_response": True,
                    }
                )

        denied = [e for e in events if not e.granted]
        for evt in denied:
            anomalies.append(
                {
                    "anomaly_type": "access_denied",
                    "alert_level": AlertLevel.MEDIUM,
                    "details": {
                        "person": evt.person_name,
                        "zone": evt.zone,
                        "badge": evt.badge_id,
                    },
                    "requires_response": False,
                }
            )

        return anomalies

    async def evaluate_policies(
        self,
        events: list[AccessEvent],
    ) -> list[dict[str, Any]]:
        """Evaluate events against zone policies."""
        logger.info(
            "physical_access.evaluate_policies",
            event_count=len(events),
        )
        violations: list[dict[str, Any]] = []

        for evt in events:
            policy_data = _ZONE_POLICIES.get(evt.zone)
            if not policy_data:
                continue
            policy = ZonePolicy(
                zone_id=evt.zone,
                zone_name=evt.zone,
                max_occupancy=policy_data["max_occupancy"],
                requires_escort=policy_data["escort"],
                restricted_hours_start=policy_data["start"],
                restricted_hours_end=policy_data["end"],
                allowed_roles=policy_data["roles"],
                mfa_required=policy_data["mfa"],
            )
            if evt.after_hours and policy.requires_escort:
                violations.append(
                    {
                        "type": "after_hours_no_escort",
                        "event_id": evt.event_id,
                        "person": evt.person_name,
                        "zone": evt.zone,
                        "policy": "escort_required",
                        "level": AlertLevel.HIGH,
                    }
                )
            if evt.access_type == AccessType.VISITOR_PASS and policy.mfa_required:
                violations.append(
                    {
                        "type": "visitor_mfa_bypass",
                        "event_id": evt.event_id,
                        "person": evt.person_name,
                        "zone": evt.zone,
                        "policy": "mfa_required",
                        "level": AlertLevel.CRITICAL,
                    }
                )

        return violations

    async def generate_alerts(
        self,
        anomalies: list[dict[str, Any]],
        violations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Generate actionable alerts."""
        logger.info(
            "physical_access.generate_alerts",
            anomaly_count=len(anomalies),
            violation_count=len(violations),
        )
        alerts: list[dict[str, Any]] = []
        now = time.time()

        for idx, anom in enumerate(anomalies):
            if anom.get("requires_response"):
                alerts.append(
                    {
                        "alert_id": f"PA-{idx:04d}",
                        "type": anom["anomaly_type"],
                        "level": anom["alert_level"],
                        "details": anom["details"],
                        "timestamp": now,
                        "source": "anomaly",
                    }
                )

        for idx, viol in enumerate(violations):
            alerts.append(
                {
                    "alert_id": f"PV-{idx:04d}",
                    "type": viol["type"],
                    "level": viol["level"],
                    "details": viol,
                    "timestamp": now,
                    "source": "policy_violation",
                }
            )

        return alerts
