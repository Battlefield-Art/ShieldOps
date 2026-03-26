"""IoT/OT Security Agent — Tool functions for device discovery and protection."""

from __future__ import annotations

import hashlib
import time
from typing import Any

import structlog

from .models import (
    BehaviorProfile,
    DeviceAnomaly,
    DeviceCategory,
    DeviceVulnerability,
    IoTDevice,
    SegmentationPolicy,
    ThreatLevel,
)

logger = structlog.get_logger()

# Simulated IoT/OT device inventory per network zone
_SAMPLE_DEVICES: dict[str, list[dict[str, Any]]] = {
    "iot": [
        {
            "name": "temp-sensor-floor3-01",
            "ip": "10.50.1.10",
            "mac": "AA:BB:CC:01:01:01",
            "category": DeviceCategory.IOT_SENSOR,
            "manufacturer": "Honeywell",
            "firmware": "3.2.1",
            "protocol": "MQTT",
            "managed": True,
            "ai_connected": True,
            "ml_pipeline": "hvac-optimization-v2",
        },
        {
            "name": "smart-cam-lobby-02",
            "ip": "10.50.1.20",
            "mac": "AA:BB:CC:02:02:02",
            "category": DeviceCategory.SMART_CAMERA,
            "manufacturer": "Hikvision",
            "firmware": "5.4.0",
            "protocol": "RTSP",
            "managed": False,
            "ai_connected": True,
            "ml_pipeline": "facial-recognition-v1",
        },
        {
            "name": "badge-reader-main-03",
            "ip": "10.50.1.30",
            "mac": "AA:BB:CC:03:03:03",
            "category": DeviceCategory.BUILDING_AUTOMATION,
            "manufacturer": "HID Global",
            "firmware": "2.1.0",
            "protocol": "BACnet",
            "managed": True,
            "ai_connected": False,
            "ml_pipeline": "",
        },
    ],
    "ot": [
        {
            "name": "plc-assembly-line-01",
            "ip": "10.60.1.10",
            "mac": "DD:EE:FF:01:01:01",
            "category": DeviceCategory.OT_CONTROLLER,
            "manufacturer": "Siemens",
            "firmware": "4.5.2",
            "protocol": "Modbus",
            "managed": True,
            "ai_connected": False,
            "ml_pipeline": "",
        },
        {
            "name": "scada-hmi-control-02",
            "ip": "10.60.1.20",
            "mac": "DD:EE:FF:02:02:02",
            "category": DeviceCategory.OT_CONTROLLER,
            "manufacturer": "Schneider Electric",
            "firmware": "3.0.1",
            "protocol": "OPC-UA",
            "managed": True,
            "ai_connected": True,
            "ml_pipeline": "predictive-maint-v3",
        },
        {
            "name": "rtu-substation-03",
            "ip": "10.60.1.30",
            "mac": "DD:EE:FF:03:03:03",
            "category": DeviceCategory.OT_CONTROLLER,
            "manufacturer": "ABB",
            "firmware": "2.8.0",
            "protocol": "DNP3",
            "managed": False,
            "ai_connected": False,
            "ml_pipeline": "",
        },
    ],
    "edge": [
        {
            "name": "edge-gpu-node-01",
            "ip": "10.70.1.10",
            "mac": "11:22:33:01:01:01",
            "category": DeviceCategory.EDGE_AI,
            "manufacturer": "NVIDIA",
            "firmware": "JetPack-5.1.2",
            "protocol": "gRPC",
            "managed": True,
            "ai_connected": True,
            "ml_pipeline": "defect-detection-v4",
        },
        {
            "name": "edge-inference-02",
            "ip": "10.70.1.20",
            "mac": "11:22:33:02:02:02",
            "category": DeviceCategory.EDGE_AI,
            "manufacturer": "Intel",
            "firmware": "OpenVINO-2024.1",
            "protocol": "gRPC",
            "managed": True,
            "ai_connected": True,
            "ml_pipeline": "quality-inspect-v2",
        },
        {
            "name": "medical-infusion-03",
            "ip": "10.70.1.30",
            "mac": "11:22:33:03:03:03",
            "category": DeviceCategory.MEDICAL_DEVICE,
            "manufacturer": "Baxter",
            "firmware": "1.4.0",
            "protocol": "HL7",
            "managed": False,
            "ai_connected": False,
            "ml_pipeline": "",
        },
    ],
}

# Known IoT/OT CVEs
_KNOWN_IOT_CVES: dict[str, dict[str, Any]] = {
    "CVE-2023-3595": {
        "desc": "Rockwell Automation ControlLogix RCE",
        "severity": ThreatLevel.CRITICAL,
        "cvss": 9.8,
        "firmware": "<=31.011",
        "patch": True,
        "exploitable": True,
    },
    "CVE-2023-34362": {
        "desc": "MOVEit Transfer SQL injection (OT supply chain)",
        "severity": ThreatLevel.CRITICAL,
        "cvss": 9.1,
        "firmware": "all",
        "patch": True,
        "exploitable": True,
    },
    "CVE-2024-3400": {
        "desc": "PAN-OS GlobalProtect gateway RCE (IoT VPN)",
        "severity": ThreatLevel.CRITICAL,
        "cvss": 10.0,
        "firmware": "<=11.1.2-h3",
        "patch": True,
        "exploitable": True,
    },
    "CVE-2023-6548": {
        "desc": "Citrix NetScaler RCE (IoT mgmt plane)",
        "severity": ThreatLevel.HIGH,
        "cvss": 8.8,
        "firmware": "<=14.1-12.35",
        "patch": True,
        "exploitable": True,
    },
    "CVE-2023-46747": {
        "desc": "BIG-IP auth bypass (OT network gateway)",
        "severity": ThreatLevel.HIGH,
        "cvss": 8.1,
        "firmware": "<=17.1.0",
        "patch": True,
        "exploitable": False,
    },
    "CVE-2024-21762": {
        "desc": "FortiOS out-of-bound write (OT firewall)",
        "severity": ThreatLevel.HIGH,
        "cvss": 7.5,
        "firmware": "<=7.4.2",
        "patch": True,
        "exploitable": True,
    },
    "CVE-2023-44221": {
        "desc": "SonicWall SMA command injection (IoT VPN)",
        "severity": ThreatLevel.MEDIUM,
        "cvss": 6.5,
        "firmware": "<=10.2.1.9",
        "patch": False,
        "exploitable": False,
    },
    "CVE-2023-20198": {
        "desc": "Cisco IOS XE web UI privilege escalation",
        "severity": ThreatLevel.CRITICAL,
        "cvss": 10.0,
        "firmware": "<=17.9",
        "patch": True,
        "exploitable": True,
    },
}


class IoTOTSecurityToolkit:
    """Tools for IoT/OT device discovery, profiling, and protection."""

    def __init__(
        self,
        network_scanner: Any | None = None,
        ot_connector: Any | None = None,
    ) -> None:
        self._network_scanner = network_scanner
        self._ot_connector = ot_connector
        self._discovery_cache: dict[str, list[IoTDevice]] = {}

    async def discover_devices(
        self,
        tenant_id: str,
        network_zones: list[str] | None = None,
    ) -> list[IoTDevice]:
        """Passive device discovery via network traffic analysis."""
        logger.info(
            "iot_ot_security.discover_devices",
            tenant_id=tenant_id,
            zones=network_zones,
        )
        network_zones = network_zones or ["iot", "ot", "edge"]
        devices: list[IoTDevice] = []
        now = time.time()

        for zone in network_zones:
            zone_devices = _SAMPLE_DEVICES.get(zone, [])
            for dev in zone_devices:
                dev_hash = hashlib.md5(  # noqa: S324  # nosec B324
                    dev["ip"].encode(),
                ).hexdigest()[:8]  # noqa: S324
                devices.append(
                    IoTDevice(
                        id=f"dev-{dev_hash}",
                        name=dev["name"],
                        ip_address=dev["ip"],
                        mac_address=dev["mac"],
                        category=dev["category"],
                        manufacturer=dev["manufacturer"],
                        firmware_version=dev["firmware"],
                        protocol=dev["protocol"],
                        is_managed=dev["managed"],
                        is_ai_connected=dev["ai_connected"],
                        ml_pipeline=dev["ml_pipeline"],
                        network_zone=zone,
                        last_seen=now,
                    )
                )

        cache_key = f"{tenant_id}:{','.join(network_zones)}"
        self._discovery_cache[cache_key] = devices
        return devices

    async def profile_behavior(
        self,
        devices: list[IoTDevice],
    ) -> list[BehaviorProfile]:
        """Build behavioral baselines for each device."""
        logger.info(
            "iot_ot_security.profile_behavior",
            device_count=len(devices),
        )
        profiles: list[BehaviorProfile] = []

        protocol_ports: dict[str, list[int]] = {
            "MQTT": [1883, 8883],
            "RTSP": [554, 8554],
            "BACnet": [47808],
            "Modbus": [502],
            "OPC-UA": [4840, 4843],
            "DNP3": [20000],
            "gRPC": [50051, 443],
            "HL7": [2575],
        }

        for dev in devices:
            seed = int(
                hashlib.md5(  # noqa: S324  # nosec B324
                    dev.id.encode(),
                ).hexdigest()[:8],  # noqa: S324
                16,
            )
            avg_bytes = float((seed % 5000) + 500)
            peak_bytes = avg_bytes * (1.5 + (seed % 10) / 10)

            ai_flow = ""
            if dev.is_ai_connected:
                ai_flow = f"sensor->edge->{dev.ml_pipeline}->cloud-ingest"

            profiles.append(
                BehaviorProfile(
                    device_id=dev.id,
                    normal_protocols=[dev.protocol],
                    normal_destinations=[
                        f"10.{(seed % 4) + 50}.0.1",
                        f"10.{(seed % 4) + 50}.0.254",
                    ],
                    avg_bytes_per_hour=avg_bytes,
                    peak_bytes_per_hour=peak_bytes,
                    expected_ports=protocol_ports.get(dev.protocol, [443]),
                    ai_data_flow_pattern=ai_flow,
                    baseline_confidence=0.85 + (seed % 10) / 100,
                )
            )

        return profiles

    async def detect_anomalies(
        self,
        devices: list[IoTDevice],
        profiles: list[BehaviorProfile],
    ) -> list[DeviceAnomaly]:
        """Detect behavioral anomalies against baselines."""
        logger.info(
            "iot_ot_security.detect_anomalies",
            device_count=len(devices),
        )
        anomalies: list[DeviceAnomaly] = []
        now = time.time()

        scenarios: list[dict[str, Any]] = [
            {
                "device_name": "smart-cam-lobby-02",
                "type": "data_exfiltration",
                "desc": (
                    "Camera streaming ML model weights "
                    "to external IP 203.0.113.50 "
                    "via HTTPS — possible model theft"
                ),
                "threat": ThreatLevel.CRITICAL,
                "confidence": 0.93,
                "dest": "203.0.113.50",
                "proto": "HTTPS",
            },
            {
                "device_name": "plc-assembly-line-01",
                "type": "unauthorized_protocol",
                "desc": (
                    "PLC communicating via Telnet "
                    "instead of Modbus — possible "
                    "command injection attempt"
                ),
                "threat": ThreatLevel.CRITICAL,
                "confidence": 0.91,
                "dest": "10.60.1.254",
                "proto": "Telnet",
            },
            {
                "device_name": "edge-gpu-node-01",
                "type": "ai_pipeline_tampering",
                "desc": (
                    "Edge AI node receiving unsigned "
                    "model update from untrusted "
                    "source — possible model poisoning"
                ),
                "threat": ThreatLevel.HIGH,
                "confidence": 0.88,
                "dest": "198.51.100.10",
                "proto": "gRPC",
            },
            {
                "device_name": "rtu-substation-03",
                "type": "lateral_movement",
                "desc": ("Unmanaged RTU scanning IT network ports — OT-to-IT lateral movement"),
                "threat": ThreatLevel.HIGH,
                "confidence": 0.86,
                "dest": "10.10.0.0/16",
                "proto": "TCP",
            },
            {
                "device_name": "medical-infusion-03",
                "type": "firmware_callback",
                "desc": (
                    "Medical device contacting unknown "
                    "firmware update server — possible "
                    "supply chain compromise"
                ),
                "threat": ThreatLevel.HIGH,
                "confidence": 0.82,
                "dest": "192.0.2.99",
                "proto": "HTTP",
            },
            {
                "device_name": "temp-sensor-floor3-01",
                "type": "data_volume_spike",
                "desc": (
                    "Sensor sending 50x normal data "
                    "volume to ML pipeline — training "
                    "data exfiltration or sensor abuse"
                ),
                "threat": ThreatLevel.MEDIUM,
                "confidence": 0.79,
                "dest": "10.50.0.1",
                "proto": "MQTT",
            },
        ]

        dev_by_name = {d.name: d for d in devices}
        for i, sc in enumerate(scenarios):
            dev = dev_by_name.get(sc["device_name"])
            if not dev:
                continue
            anomalies.append(
                DeviceAnomaly(
                    id=f"anom-{i:04d}",
                    device_id=dev.id,
                    device_name=dev.name,
                    anomaly_type=sc["type"],
                    description=sc["desc"],
                    threat_level=sc["threat"],
                    confidence=sc["confidence"],
                    source_ip=dev.ip_address,
                    dest_ip=sc["dest"],
                    protocol=sc["proto"],
                    timestamp=now - (i * 120),
                )
            )

        return anomalies

    async def assess_vulnerabilities(
        self,
        devices: list[IoTDevice],
    ) -> list[DeviceVulnerability]:
        """Assess device firmware vulnerabilities."""
        logger.info(
            "iot_ot_security.assess_vulnerabilities",
            device_count=len(devices),
        )
        vulns: list[DeviceVulnerability] = []
        cve_list = list(_KNOWN_IOT_CVES.items())

        for dev in devices:
            dev_hash = hashlib.md5(  # noqa: S324  # nosec B324
                dev.id.encode(),
            ).hexdigest()  # noqa: S324
            seed = int(dev_hash[:8], 16)
            count = (seed % 2) + 1

            for j in range(count):
                idx = (seed + j) % len(cve_list)
                cve_id, cve_data = cve_list[idx]
                vulns.append(
                    DeviceVulnerability(
                        id=f"vuln-{dev_hash[:6]}-{j}",
                        device_id=dev.id,
                        device_name=dev.name,
                        cve_id=cve_id,
                        severity=cve_data["severity"],
                        cvss_score=cve_data["cvss"],
                        firmware_affected=cve_data["firmware"],
                        patch_available=cve_data["patch"],
                        description=cve_data["desc"],
                        exploitable=cve_data["exploitable"],
                    )
                )

        return vulns

    async def enforce_segmentation(
        self,
        devices: list[IoTDevice],
        anomalies: list[DeviceAnomaly],
    ) -> list[SegmentationPolicy]:
        """Enforce micro-segmentation policies for devices."""
        logger.info(
            "iot_ot_security.enforce_segmentation",
            device_count=len(devices),
            anomaly_count=len(anomalies),
        )
        policies: list[SegmentationPolicy] = []
        # Isolate devices with critical anomalies
        critical_ids: set[str] = set()
        for anom in anomalies:
            if anom.threat_level in (
                ThreatLevel.CRITICAL,
                ThreatLevel.HIGH,
            ):
                critical_ids.add(anom.device_id)

        for dev in devices:
            dev_hash = hashlib.md5(  # noqa: S324  # nosec B324
                dev.id.encode(),
            ).hexdigest()[:6]  # noqa: S324

            if dev.id in critical_ids:
                # Quarantine: deny all except
                # management traffic
                policies.append(
                    SegmentationPolicy(
                        id=f"seg-quarantine-{dev_hash}",
                        device_id=dev.id,
                        device_name=dev.name,
                        source_zone=dev.network_zone,
                        dest_zone="quarantine",
                        allowed_protocols=["SSH"],
                        allowed_ports=[22],
                        action="quarantine",
                        applied=True,
                        success=True,
                    )
                )
            elif not dev.is_managed:
                # Unmanaged: restrict to zone-local only
                policies.append(
                    SegmentationPolicy(
                        id=f"seg-restrict-{dev_hash}",
                        device_id=dev.id,
                        device_name=dev.name,
                        source_zone=dev.network_zone,
                        dest_zone=dev.network_zone,
                        allowed_protocols=[dev.protocol],
                        allowed_ports=[443],
                        action="restrict",
                        applied=True,
                        success=True,
                    )
                )
            else:
                # Managed: allow zone traffic, block
                # cross-zone by default
                policies.append(
                    SegmentationPolicy(
                        id=f"seg-allow-{dev_hash}",
                        device_id=dev.id,
                        device_name=dev.name,
                        source_zone=dev.network_zone,
                        dest_zone=dev.network_zone,
                        allowed_protocols=[
                            dev.protocol,
                            "HTTPS",
                        ],
                        allowed_ports=[443, 8443],
                        action="allow",
                        applied=True,
                        success=True,
                    )
                )

        return policies
