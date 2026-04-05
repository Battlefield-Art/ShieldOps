"""AWS GuardDuty findings to OCSF SecurityFinding mapper."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.ingestion.ocsf.models import OCSFBaseEvent, OCSFSecurityFinding

logger = structlog.get_logger()

_SEVERITY_RANGES: list[tuple[float, str]] = [
    (7.0, "critical"),
    (4.0, "high"),
    (2.0, "medium"),
    (1.0, "low"),
    (0.0, "informational"),
]


def _severity_label(score: float) -> str:
    for threshold, label in _SEVERITY_RANGES:
        if score >= threshold:
            return label
    return "informational"


class GuardDutyMapper:
    """Transform AWS GuardDuty findings into OCSFSecurityFinding."""

    def map(self, raw_event: dict[str, Any]) -> OCSFBaseEvent:
        """Map a GuardDuty finding to an OCSF SecurityFinding."""
        finding_id = raw_event.get("Id", raw_event.get("id", ""))
        title = raw_event.get("Title", raw_event.get("title", ""))
        description = raw_event.get("Description", raw_event.get("description", ""))
        severity_score = float(raw_event.get("Severity", raw_event.get("severity", 0)))
        severity = _severity_label(severity_score)
        confidence = float(raw_event.get("Confidence", raw_event.get("confidence", 0)))

        first_seen = _parse_time(
            raw_event.get("Service", {}).get("EventFirstSeen") or raw_event.get("CreatedAt", "")
        )
        last_seen = _parse_time(
            raw_event.get("Service", {}).get("EventLastSeen") or raw_event.get("UpdatedAt", "")
        )
        timestamp = last_seen or first_seen or datetime.now(UTC)

        # Extract affected resource
        resource_raw = raw_event.get("Resource", raw_event.get("resource", {}))
        resources: list[dict[str, Any]] = []
        if resource_raw and isinstance(resource_raw, dict):
            resource_type = resource_raw.get("ResourceType", "unknown")
            instance = resource_raw.get("InstanceDetails", {})
            resources.append(
                {
                    "type": resource_type,
                    "uid": instance.get("InstanceId", ""),
                    "name": instance.get("InstanceId", ""),
                    "details": {k: v for k, v in resource_raw.items() if k not in {"ResourceType"}},
                }
            )

        finding_type = raw_event.get("Type", raw_event.get("type", ""))

        normalized: dict[str, Any] = {
            "category_uid": 2001,
            "class_uid": 2001,
            "finding_id": str(finding_id),
            "title": title,
            "description": description,
            "severity": severity,
            "severity_score": severity_score,
            "confidence": confidence,
            "finding_type": finding_type,
        }

        return OCSFSecurityFinding(
            timestamp=timestamp,
            severity=severity,
            source_provider="guardduty",
            source_type=finding_type or "finding",
            raw_event=raw_event,
            normalized=normalized,
            finding_id=str(finding_id),
            title=title,
            confidence=confidence,
            first_seen=first_seen,
            last_seen=last_seen,
            resources=resources,
        )


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        if isinstance(value, str):
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        return None
    except (ValueError, TypeError):
        logger.warning("guardduty_unparseable_time", value=value)
        return None
