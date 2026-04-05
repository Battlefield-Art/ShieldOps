"""Azure Activity Log to OCSF APIActivity mapper."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.ingestion.ocsf.models import OCSFAPIActivity, OCSFBaseEvent

logger = structlog.get_logger()


class AzureActivityMapper:
    """Transform Azure Activity Log events into OCSFAPIActivity."""

    def map(self, raw_event: dict[str, Any]) -> OCSFBaseEvent:
        """Map an Azure Activity Log event to an OCSF APIActivity event."""
        operation = raw_event.get("operationName", raw_event.get("operationId", ""))
        caller = raw_event.get(
            "caller", raw_event.get("identity", {}).get("claim", {}).get("name", "")
        )
        if isinstance(caller, dict):
            caller = caller.get("name", str(caller))

        status_obj = raw_event.get("status", {})
        if isinstance(status_obj, dict):
            status_value = status_obj.get("value", "")
        else:
            status_value = str(status_obj)

        http_request = raw_event.get("httpRequest", {})
        response_code = _safe_int(
            http_request.get("statusCode", 0) if isinstance(http_request, dict) else 0
        )
        # Map status string to response code if no HTTP code
        if response_code == 0:
            response_code = _status_to_code(status_value)

        # Extract service from resourceProviderName or operationName
        resource_provider = raw_event.get(
            "resourceProviderName",
            operation.split("/")[0] if "/" in operation else "",
        )

        properties = raw_event.get("properties", {})
        request_params = properties if isinstance(properties, dict) else {}

        timestamp = _parse_time(raw_event.get("eventTimestamp", raw_event.get("time", "")))
        level = raw_event.get("level", "Informational")
        severity = _level_to_severity(level)

        normalized: dict[str, Any] = {
            "category_uid": 6003,
            "class_uid": 6003,
            "api_name": operation,
            "actor": caller,
            "service": resource_provider,
            "response_code": response_code,
            "status": status_value,
            "level": level,
        }

        return OCSFAPIActivity(
            timestamp=timestamp,
            severity=severity,
            source_provider="azure_activity",
            source_type=operation,
            raw_event=raw_event,
            normalized=normalized,
            api_name=operation,
            service=resource_provider,
            request_params=request_params,
            response_code=response_code,
            actor=str(caller),
        )


def _parse_time(value: Any) -> datetime:
    if not value:
        return datetime.now(UTC)
    try:
        if isinstance(value, str):
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        logger.warning("azure_activity_unparseable_time", value=value)
    return datetime.now(UTC)


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0


def _status_to_code(status: str) -> int:
    status_lower = status.lower() if isinstance(status, str) else ""
    if "succeeded" in status_lower or "success" in status_lower:
        return 200
    if "failed" in status_lower or "failure" in status_lower:
        return 500
    if "forbidden" in status_lower:
        return 403
    return 0


def _level_to_severity(level: str) -> str:
    mapping: dict[str, str] = {
        "critical": "critical",
        "error": "high",
        "warning": "medium",
        "informational": "informational",
    }
    if not isinstance(level, str):
        return "informational"
    return mapping.get(level.lower(), "informational")
