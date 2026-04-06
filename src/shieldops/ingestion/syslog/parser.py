"""RFC 5424 syslog wire-format parser.

Thin wrapper around the regex used by the OCSF syslog mapper so that
listeners can validate and extract structured fields before handing the
raw line to the pipeline.
"""

from __future__ import annotations

from typing import Any

from shieldops.ingestion.ocsf.mappers.syslog import (
    _RFC5424_RE,
    _parse_structured_data,
    _parse_syslog_time,
)


def parse_rfc5424(line: str) -> dict[str, Any]:
    """Parse an RFC 5424 syslog line into a structured dict.

    The returned dict always contains a ``message`` key holding the raw line
    so that downstream OCSF mapping can re-parse it. Parser failures return
    ``{"message": line, "parse_error": True}``.

    Args:
        line: Raw syslog line (single message, no trailing newline).

    Returns:
        Dict with fields: pri, version, facility, severity_code, timestamp,
        hostname, app_name, procid, msgid, structured_data, msg, message.
    """
    line = line.strip()
    match = _RFC5424_RE.match(line)
    if not match:
        return {"message": line, "parse_error": True}

    pri = int(match.group("pri"))
    severity_code = pri % 8
    facility = pri // 8
    timestamp = _parse_syslog_time(match.group("timestamp"))

    return {
        "message": line,
        "pri": pri,
        "version": int(match.group("version")),
        "facility": facility,
        "severity_code": severity_code,
        "timestamp": timestamp.isoformat(),
        "hostname": match.group("hostname"),
        "app_name": match.group("app_name"),
        "procid": match.group("procid"),
        "msgid": match.group("msgid"),
        "structured_data": _parse_structured_data(match.group("structured_data")),
        "msg": match.group("message").strip(),
        "parse_error": False,
    }
