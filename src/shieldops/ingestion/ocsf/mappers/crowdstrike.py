"""CrowdStrike detections to OCSF SecurityFinding mapper."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.ingestion.ocsf.models import OCSFBaseEvent, OCSFSecurityFinding

logger = structlog.get_logger()

_SEVERITY_MAP: dict[str, str] = {
    "1": "informational",
    "2": "low",
    "3": "medium",
    "4": "high",
    "5": "critical",
}


class CrowdStrikeMapper:
    """Transform CrowdStrike detection events into OCSFSecurityFinding."""

    def map(self, raw_event: dict[str, Any]) -> OCSFBaseEvent:
        """Map a CrowdStrike detection to an OCSF SecurityFinding."""
        detection_id = str(raw_event.get("detection_id", raw_event.get("composite_id", "")))
        title = raw_event.get("detect_name", raw_event.get("description", ""))
        severity_num = str(raw_event.get("severity", raw_event.get("max_severity", "1")))
        severity = _SEVERITY_MAP.get(severity_num, "informational")
        confidence = float(raw_event.get("confidence", 0))

        first_seen = _parse_epoch(raw_event.get("first_behavior"))
        last_seen = _parse_epoch(raw_event.get("last_behavior"))
        timestamp = last_seen or first_seen or datetime.now(UTC)

        # Build resource list from device info
        device = raw_event.get("device", {})
        resources: list[dict[str, Any]] = []
        if device:
            resources.append(
                {
                    "type": "device",
                    "uid": device.get("device_id", ""),
                    "name": device.get("hostname", ""),
                    "os": device.get("os_version", ""),
                    "platform": device.get("platform_name", ""),
                }
            )

        # Tactic/technique metadata
        behaviors = raw_event.get("behaviors", [])
        tactics: list[str] = []
        techniques: list[str] = []
        for b in behaviors if isinstance(behaviors, list) else []:
            if isinstance(b, dict):
                tactic = b.get("tactic", "")
                technique = b.get("technique", "")
                if tactic and tactic not in tactics:
                    tactics.append(tactic)
                if technique and technique not in techniques:
                    techniques.append(technique)

        normalized: dict[str, Any] = {
            "category_uid": 2001,
            "class_uid": 2001,
            "finding_id": detection_id,
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "tactics": tactics,
            "techniques": techniques,
        }

        return OCSFSecurityFinding(
            timestamp=timestamp,
            severity=severity,
            source_provider="crowdstrike",
            source_type="detection",
            raw_event=raw_event,
            normalized=normalized,
            finding_id=detection_id,
            title=title,
            confidence=confidence,
            first_seen=first_seen,
            last_seen=last_seen,
            resources=resources,
        )


def _parse_epoch(value: Any) -> datetime | None:
    """Parse epoch seconds/milliseconds or ISO string, return None on failure."""
    if value is None:
        return None
    try:
        if isinstance(value, str):
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        ts = float(value)
        # If value > 1e12, treat as milliseconds
        if ts > 1e12:
            ts = ts / 1000.0
        return datetime.fromtimestamp(ts, tz=UTC)
    except (ValueError, TypeError, OSError):
        logger.warning("crowdstrike_unparseable_time", value=value)
        return None
