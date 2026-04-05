"""CloudTrail to OCSF mapper.

Maps AWS CloudTrail events to:
- OCSFAuthenticationEvent for ConsoleLogin, AssumeRole
- OCSFAPIActivity for all other API calls
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.ingestion.ocsf.models import (
    OCSFAPIActivity,
    OCSFAuthenticationEvent,
    OCSFBaseEvent,
)

logger = structlog.get_logger()

_AUTH_EVENT_NAMES = {"ConsoleLogin", "AssumeRole", "GetSessionToken", "GetFederationToken"}


class CloudTrailMapper:
    """Transform AWS CloudTrail events into OCSF models."""

    def map(self, raw_event: dict[str, Any]) -> OCSFBaseEvent:
        """Map a CloudTrail event to the appropriate OCSF model."""
        event_name = raw_event.get("eventName", "")

        if event_name in _AUTH_EVENT_NAMES:
            return self._map_auth(raw_event, event_name)
        return self._map_api(raw_event, event_name)

    def _map_auth(self, raw_event: dict[str, Any], event_name: str) -> OCSFAuthenticationEvent:
        user_identity = raw_event.get("userIdentity", {})
        user = user_identity.get("userName", user_identity.get("arn", ""))
        src_ip = raw_event.get("sourceIPAddress", "")
        response = raw_event.get("responseElements", {})

        # ConsoleLogin has responseElements.ConsoleLogin = "Success"/"Failure"
        status_raw = ""
        if event_name == "ConsoleLogin":
            status_raw = (response.get("ConsoleLogin", "") if response else "").lower()
        else:
            # AssumeRole etc. — errorCode absent means success
            status_raw = "failure" if raw_event.get("errorCode") else "success"

        action = "logout" if event_name == "Logout" else "login"
        timestamp = _parse_time(raw_event.get("eventTime", ""))

        normalized: dict[str, Any] = {
            "category_uid": 3001,
            "class_uid": 3002,
            "activity_name": event_name,
            "user": user,
            "src_ip": src_ip,
            "status": status_raw,
            "action": action,
        }

        return OCSFAuthenticationEvent(
            timestamp=timestamp,
            severity=_severity_from_status(status_raw),
            source_provider="cloudtrail",
            source_type=event_name,
            raw_event=raw_event,
            normalized=normalized,
            user=user,
            src_ip=src_ip,
            dst_ip="",
            action=action,
            status=status_raw,
        )

    def _map_api(self, raw_event: dict[str, Any], event_name: str) -> OCSFAPIActivity:
        user_identity = raw_event.get("userIdentity", {})
        actor = user_identity.get("arn", user_identity.get("userName", ""))
        service = raw_event.get("eventSource", "")
        request_params = raw_event.get("requestParameters") or {}
        error_code = raw_event.get("errorCode", "")
        timestamp = _parse_time(raw_event.get("eventTime", ""))

        response_code = 403 if error_code == "AccessDenied" else (0 if error_code else 200)

        normalized: dict[str, Any] = {
            "category_uid": 6003,
            "class_uid": 6003,
            "activity_name": event_name,
            "actor": actor,
            "service": service,
            "response_code": response_code,
        }

        severity = "high" if error_code == "AccessDenied" else "informational"

        return OCSFAPIActivity(
            timestamp=timestamp,
            severity=severity,
            source_provider="cloudtrail",
            source_type=event_name,
            raw_event=raw_event,
            normalized=normalized,
            api_name=event_name,
            service=service,
            request_params=request_params,
            response_code=response_code,
            actor=actor,
        )


def _parse_time(time_str: str) -> datetime:
    """Parse CloudTrail timestamp, falling back to now(UTC)."""
    if not time_str:
        return datetime.now(UTC)
    try:
        return datetime.fromisoformat(time_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        logger.warning("cloudtrail_unparseable_time", time_str=time_str)
        return datetime.now(UTC)


def _severity_from_status(status: str) -> str:
    return "medium" if status == "failure" else "informational"
