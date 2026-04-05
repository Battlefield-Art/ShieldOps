"""VPC Flow Logs to OCSF NetworkActivity mapper."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.ingestion.ocsf.models import OCSFBaseEvent, OCSFNetworkActivity

logger = structlog.get_logger()

_PROTOCOL_MAP: dict[str, str] = {
    "6": "tcp",
    "17": "udp",
    "1": "icmp",
    "58": "icmpv6",
}


class VPCFlowMapper:
    """Transform AWS VPC Flow Log records into OCSFNetworkActivity."""

    def map(self, raw_event: dict[str, Any]) -> OCSFBaseEvent:
        """Map a VPC Flow Log record to an OCSF NetworkActivity event.

        Handles both dict-format and space-separated string-format flow logs.
        """
        if isinstance(raw_event.get("message"), str):
            return self._map_from_string(raw_event)
        return self._map_from_dict(raw_event)

    def _map_from_dict(self, raw_event: dict[str, Any]) -> OCSFNetworkActivity:
        src_ip = str(raw_event.get("srcaddr", raw_event.get("src_ip", "")))
        src_port = _safe_int(raw_event.get("srcport", raw_event.get("src_port", 0)))
        dst_ip = str(raw_event.get("dstaddr", raw_event.get("dst_ip", "")))
        dst_port = _safe_int(raw_event.get("dstport", raw_event.get("dst_port", 0)))
        protocol_num = str(raw_event.get("protocol", ""))
        protocol = _PROTOCOL_MAP.get(protocol_num, protocol_num)
        bytes_total = _safe_int(raw_event.get("bytes", 0))
        packets = _safe_int(raw_event.get("packets", 0))
        action_raw = str(raw_event.get("action", "ACCEPT")).upper()
        action = "allow" if action_raw == "ACCEPT" else "deny"

        start_ts = _parse_epoch(raw_event.get("start"))
        timestamp = start_ts or datetime.now(UTC)

        normalized: dict[str, Any] = {
            "category_uid": 4001,
            "class_uid": 4001,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "bytes": bytes_total,
            "packets": packets,
            "action": action,
        }

        return OCSFNetworkActivity(
            timestamp=timestamp,
            severity="informational" if action == "allow" else "low",
            source_provider="vpc_flow",
            source_type="flow_log",
            raw_event=raw_event,
            normalized=normalized,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            bytes_in=bytes_total,
            bytes_out=0,
            action=action,
        )

    def _map_from_string(self, raw_event: dict[str, Any]) -> OCSFNetworkActivity:
        """Parse space-separated VPC flow log line."""
        message = raw_event.get("message", "")
        parts = message.split()
        # Standard v2 format (14 space-separated fields):
        # version account-id eni srcaddr dstaddr srcport dstport
        # protocol packets bytes start end action log-status
        if len(parts) < 14:
            logger.warning("vpc_flow_short_record", parts_count=len(parts))
            return OCSFNetworkActivity(
                source_provider="vpc_flow",
                source_type="flow_log",
                raw_event=raw_event,
            )

        parsed = {
            "srcaddr": parts[3],
            "dstaddr": parts[4],
            "srcport": parts[5],
            "dstport": parts[6],
            "protocol": parts[7],
            "packets": parts[8],
            "bytes": parts[9],
            "start": parts[10],
            "action": parts[12],
        }
        return self._map_from_dict({**raw_event, **parsed})


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0


def _parse_epoch(value: Any) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=UTC)
    except (ValueError, TypeError, OSError):
        return None
