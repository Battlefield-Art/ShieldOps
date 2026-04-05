"""RFC 5424 syslog to OCSF BaseEvent mapper."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.ingestion.ocsf.models import OCSFBaseEvent

logger = structlog.get_logger()

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
_RFC5424_RE = re.compile(
    r"<(?P<pri>\d{1,3})>"
    r"(?P<version>\d{1,2})\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<app_name>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<structured_data>(?:\[.*?\])+|-)\s*"
    r"(?P<message>.*)",
    re.DOTALL,
)

# Structured-data element: [id key="val" key="val"]
_SD_ELEMENT_RE = re.compile(r"\[(?P<id>[^\s\]]+)(?P<params>[^\]]*)\]")
_SD_PARAM_RE = re.compile(r'(\S+)="([^"]*)"')

_SEVERITY_FROM_FACILITY: dict[int, str] = {
    0: "critical",  # Emergency
    1: "critical",  # Alert
    2: "critical",  # Critical
    3: "high",  # Error
    4: "medium",  # Warning
    5: "low",  # Notice
    6: "informational",  # Informational
    7: "informational",  # Debug
}


class SyslogMapper:
    """Transform RFC 5424 syslog messages into OCSFBaseEvent."""

    def map(self, raw_event: dict[str, Any]) -> OCSFBaseEvent:
        """Map a syslog event to an OCSF BaseEvent.

        Accepts either:
        - {"message": "<raw syslog line>"} — parsed via regex
        - {"hostname": ..., "app_name": ..., ...} — pre-parsed fields
        """
        message = raw_event.get("message", "")

        if isinstance(message, str) and message.startswith("<"):
            return self._parse_rfc5424(message, raw_event)

        # Pre-parsed syslog dict
        return self._map_from_dict(raw_event)

    def _parse_rfc5424(self, line: str, raw_event: dict[str, Any]) -> OCSFBaseEvent:
        match = _RFC5424_RE.match(line)
        if not match:
            logger.warning("syslog_parse_failed", line_prefix=line[:80])
            return OCSFBaseEvent(
                source_provider="syslog",
                source_type="unparsed",
                raw_event=raw_event,
                normalized={"parse_error": True, "raw_message": line[:500]},
            )

        pri = int(match.group("pri"))
        severity_code = pri % 8
        facility = pri // 8
        severity = _SEVERITY_FROM_FACILITY.get(severity_code, "informational")

        timestamp = _parse_syslog_time(match.group("timestamp"))
        hostname = match.group("hostname")
        app_name = match.group("app_name")
        procid = match.group("procid")
        msgid = match.group("msgid")
        sd_raw = match.group("structured_data")
        msg = match.group("message").strip()

        structured_data = _parse_structured_data(sd_raw)

        normalized: dict[str, Any] = {
            "category_uid": 1,
            "facility": facility,
            "severity_code": severity_code,
            "hostname": hostname,
            "app_name": app_name,
            "procid": procid if procid != "-" else None,
            "msgid": msgid if msgid != "-" else None,
            "structured_data": structured_data,
            "message": msg,
        }

        return OCSFBaseEvent(
            timestamp=timestamp,
            severity=severity,
            source_provider="syslog",
            source_type=f"rfc5424/{app_name}",
            raw_event=raw_event,
            normalized=normalized,
        )

    def _map_from_dict(self, raw_event: dict[str, Any]) -> OCSFBaseEvent:
        hostname = raw_event.get("hostname", "")
        app_name = raw_event.get("app_name", "")
        severity = raw_event.get("severity", "informational")
        msg = raw_event.get("msg", raw_event.get("message", ""))
        timestamp_raw = raw_event.get("timestamp", "")

        timestamp = (
            _parse_syslog_time(timestamp_raw)
            if isinstance(timestamp_raw, str) and timestamp_raw
            else datetime.now(UTC)
        )

        normalized: dict[str, Any] = {
            "category_uid": 1,
            "hostname": hostname,
            "app_name": app_name,
            "message": str(msg),
        }

        return OCSFBaseEvent(
            timestamp=timestamp,
            severity=str(severity),
            source_provider="syslog",
            source_type=f"dict/{app_name}" if app_name else "dict",
            raw_event=raw_event,
            normalized=normalized,
        )


def _parse_syslog_time(time_str: str) -> datetime:
    if not time_str or time_str == "-":
        return datetime.now(UTC)
    try:
        return datetime.fromisoformat(time_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        pass
    # Try common syslog timestamp formats
    for fmt in ("%b %d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(time_str, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    logger.warning("syslog_unparseable_time", time_str=time_str)
    return datetime.now(UTC)


def _parse_structured_data(sd_raw: str) -> dict[str, dict[str, str]]:
    """Parse RFC 5424 structured-data into {sd_id: {key: val, ...}}."""
    if sd_raw == "-":
        return {}
    result: dict[str, dict[str, str]] = {}
    for elem_match in _SD_ELEMENT_RE.finditer(sd_raw):
        sd_id = elem_match.group("id")
        params_str = elem_match.group("params")
        params = dict(_SD_PARAM_RE.findall(params_str))
        result[sd_id] = params
    return result
