"""OT Protocol Monitor Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    OTAlert,
    OTDevice,
    OTProtocolType,
    OTThreat,
    OTThreatSeverity,
    ProtocolAnomaly,
    ProtocolEvent,
)

logger = structlog.get_logger()

_SAMPLE_DEVICES: list[dict[str, Any]] = [
    {
        "name": "PLC-Zone1-Main",
        "device_type": "PLC",
        "ip_address": "10.100.1.10",
        "protocol": "modbus",
        "vendor": "Siemens",
        "firmware_version": "4.2.1",
        "zone": "zone-1",
        "is_critical": True,
    },
    {
        "name": "RTU-Zone1-Sub",
        "device_type": "RTU",
        "ip_address": "10.100.1.11",
        "protocol": "dnp3",
        "vendor": "ABB",
        "firmware_version": "3.8.0",
        "zone": "zone-1",
        "is_critical": True,
    },
    {
        "name": "HMI-Zone2-Ops",
        "device_type": "HMI",
        "ip_address": "10.100.2.20",
        "protocol": "opc_ua",
        "vendor": "Rockwell",
        "firmware_version": "5.1.3",
        "zone": "zone-2",
        "is_critical": False,
    },
    {
        "name": "Sensor-Zone2-Temp",
        "device_type": "Sensor",
        "ip_address": "10.100.2.30",
        "protocol": "modbus",
        "vendor": "Honeywell",
        "firmware_version": "2.0.1",
        "zone": "zone-2",
        "is_critical": False,
    },
    {
        "name": "PLC-Zone3-Power",
        "device_type": "PLC",
        "ip_address": "10.100.3.10",
        "protocol": "ethernet_ip",
        "vendor": "Schneider",
        "firmware_version": "6.0.2",
        "zone": "zone-3",
        "is_critical": True,
    },
    {
        "name": "Gateway-Zone3-BACnet",
        "device_type": "Gateway",
        "ip_address": "10.100.3.50",
        "protocol": "bacnet",
        "vendor": "Johnson Controls",
        "firmware_version": "1.9.4",
        "zone": "zone-3",
        "is_critical": False,
    },
]

_SAMPLE_EVENTS: list[dict[str, Any]] = [
    {
        "source_ip": "10.100.1.10",
        "dest_ip": "10.100.1.11",
        "protocol": "modbus",
        "function_code": 3,
        "payload_size": 64,
        "register_address": 400,
        "value": 72.5,
        "is_write": False,
    },
    {
        "source_ip": "10.200.0.5",
        "dest_ip": "10.100.1.10",
        "protocol": "modbus",
        "function_code": 6,
        "payload_size": 256,
        "register_address": 100,
        "value": 999.0,
        "is_write": True,
    },
    {
        "source_ip": "10.100.2.20",
        "dest_ip": "10.100.2.30",
        "protocol": "opc_ua",
        "function_code": 0,
        "payload_size": 128,
        "register_address": 0,
        "value": 22.3,
        "is_write": False,
    },
    {
        "source_ip": "10.200.0.5",
        "dest_ip": "10.100.3.10",
        "protocol": "ethernet_ip",
        "function_code": 16,
        "payload_size": 512,
        "register_address": 200,
        "value": 0.0,
        "is_write": True,
    },
    {
        "source_ip": "10.100.3.50",
        "dest_ip": "10.100.3.10",
        "protocol": "bacnet",
        "function_code": 8,
        "payload_size": 32,
        "register_address": 50,
        "value": 18.7,
        "is_write": False,
    },
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class OTProtocolMonitorToolkit:
    """Tools for OT/ICS protocol monitoring."""

    def __init__(
        self,
        ot_connector: Any | None = None,
        threat_intel_api: Any | None = None,
    ) -> None:
        self._ot_connector = ot_connector
        self._threat_intel_api = threat_intel_api

    async def discover_devices(
        self,
        tenant_id: str,
    ) -> list[OTDevice]:
        """Discover OT/ICS devices on the network."""
        logger.info(
            "opm.discover_devices",
            tenant_id=tenant_id,
        )

        if self._ot_connector is not None:
            try:
                raw = await self._ot_connector.scan(
                    tenant_id=tenant_id,
                )
                return [OTDevice(**r) for r in raw]
            except Exception:
                logger.exception("opm.discover_devices.error")

        devices: list[OTDevice] = []
        for i, d in enumerate(_SAMPLE_DEVICES):
            devices.append(
                OTDevice(
                    id=_gen_id("OD", tenant_id, i),
                    name=d["name"],
                    device_type=d["device_type"],
                    ip_address=d["ip_address"],
                    protocol=OTProtocolType(d["protocol"]),
                    vendor=d["vendor"],
                    firmware_version=d["firmware_version"],
                    last_seen="2026-03-30T10:00:00Z",
                    zone=d["zone"],
                    is_critical=d["is_critical"],
                )
            )
        return devices

    async def monitor_protocols(
        self,
        devices: list[OTDevice],
    ) -> list[ProtocolEvent]:
        """Monitor protocol traffic for discovered devices."""
        logger.info(
            "opm.monitor_protocols",
            count=len(devices),
        )

        events: list[ProtocolEvent] = []
        for i, e in enumerate(_SAMPLE_EVENTS):
            noise = random.randint(-5, 5)  # noqa: S311
            events.append(
                ProtocolEvent(
                    id=_gen_id("PE", str(i), i),
                    timestamp=f"2026-03-30T10:{i:02d}:00Z",
                    source_ip=e["source_ip"],
                    dest_ip=e["dest_ip"],
                    protocol=OTProtocolType(e["protocol"]),
                    function_code=e["function_code"],
                    payload_size=e["payload_size"] + noise,
                    register_address=e["register_address"],
                    value=e["value"],
                    is_write=e["is_write"],
                )
            )
        return events

    async def detect_anomalies(
        self,
        events: list[ProtocolEvent],
    ) -> list[ProtocolAnomaly]:
        """Detect protocol anomalies from events."""
        logger.info(
            "opm.detect_anomalies",
            count=len(events),
        )

        anomalies: list[ProtocolAnomaly] = []
        idx = 0
        for ev in events:
            if ev.is_write and ev.source_ip.startswith("10.200"):
                anomalies.append(
                    ProtocolAnomaly(
                        id=_gen_id("PA", ev.id, idx),
                        device_id=ev.dest_ip,
                        protocol=ev.protocol,
                        anomaly_type="unauthorized_write",
                        description=(f"Write from untrusted {ev.source_ip} to {ev.dest_ip}"),
                        confidence=0.92,
                        baseline_value=0.0,
                        observed_value=ev.value,
                        evidence=[
                            f"Source: {ev.source_ip}",
                            f"FC: {ev.function_code}",
                            f"Register: {ev.register_address}",
                        ],
                    )
                )
                idx += 1
            if ev.payload_size > 200:
                anomalies.append(
                    ProtocolAnomaly(
                        id=_gen_id("PA", ev.id, idx),
                        device_id=ev.dest_ip,
                        protocol=ev.protocol,
                        anomaly_type="large_payload",
                        description=(
                            f"Oversized payload {ev.payload_size}B on {ev.protocol.value}"
                        ),
                        confidence=0.78,
                        baseline_value=64.0,
                        observed_value=float(ev.payload_size),
                        evidence=[
                            f"Size: {ev.payload_size}B",
                            f"Protocol: {ev.protocol.value}",
                        ],
                    )
                )
                idx += 1
        return anomalies

    async def classify_threats(
        self,
        anomalies: list[ProtocolAnomaly],
    ) -> list[OTThreat]:
        """Classify anomalies into OT threat categories."""
        logger.info(
            "opm.classify_threats",
            count=len(anomalies),
        )

        threats: list[OTThreat] = []
        for i, a in enumerate(anomalies):
            severity = (
                OTThreatSeverity.CRITICAL
                if a.confidence >= 0.9
                else OTThreatSeverity.HIGH
                if a.confidence >= 0.7
                else OTThreatSeverity.MEDIUM
            )
            threat_type = (
                "plc_manipulation" if a.anomaly_type == "unauthorized_write" else "protocol_abuse"
            )
            tactic = "Impair Process Control" if threat_type == "plc_manipulation" else "Collection"
            threats.append(
                OTThreat(
                    id=_gen_id("OT", a.id, i),
                    anomaly_id=a.id,
                    threat_type=threat_type,
                    severity=severity,
                    attack_vector=a.anomaly_type,
                    affected_devices=[a.device_id],
                    mitre_ics_tactic=tactic,
                    confidence=a.confidence,
                )
            )
        return threats

    async def generate_alerts(
        self,
        threats: list[OTThreat],
    ) -> list[OTAlert]:
        """Generate security alerts for classified threats."""
        logger.info(
            "opm.generate_alerts",
            count=len(threats),
        )

        alerts: list[OTAlert] = []
        for i, t in enumerate(threats):
            action = (
                "Isolate device immediately"
                if t.severity == OTThreatSeverity.CRITICAL
                else "Investigate and monitor"
            )
            alerts.append(
                OTAlert(
                    id=_gen_id("OA", t.id, i),
                    threat_id=t.id,
                    severity=t.severity,
                    title=f"{t.threat_type} on {t.affected_devices[0]}",
                    description=(f"{t.attack_vector} detected with {t.confidence:.0%} confidence"),
                    recommended_action=action,
                    notified=True,
                )
            )
        return alerts
