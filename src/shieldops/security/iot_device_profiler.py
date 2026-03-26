"""IoT Device Profiler — profile devices, detect anomalies, enforce segmentation."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ProtocolType(StrEnum):
    MQTT = "mqtt"
    COAP = "coap"
    MODBUS = "modbus"
    OPCUA = "opcua"
    HTTPS = "https"


class DeviceRisk(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class SegmentationStatus(StrEnum):
    FULLY_SEGMENTED = "fully_segmented"
    PARTIALLY_SEGMENTED = "partially_segmented"
    NOT_SEGMENTED = "not_segmented"
    BYPASS_DETECTED = "bypass_detected"
    UNKNOWN = "unknown"


# --- Models ---


class IoTDeviceRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_name: str = ""
    device_type: str = ""
    protocol: ProtocolType = ProtocolType.MQTT
    risk_level: DeviceRisk = DeviceRisk.MEDIUM
    segmentation: SegmentationStatus = SegmentationStatus.UNKNOWN
    firmware_version: str = ""
    ip_address: str = ""
    anomaly_detected: bool = False
    last_seen: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


class IoTDeviceAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str = ""
    protocol_anomalies: int = 0
    communication_peers: int = 0
    risk_factors: list[str] = Field(default_factory=list)
    analyzed_at: float = Field(default_factory=time.time)


class IoTDeviceReport(BaseModel):
    total_devices: int = 0
    high_risk_count: int = 0
    unsegmented_count: int = 0
    anomaly_count: int = 0
    by_protocol: dict[str, int] = Field(default_factory=dict)
    by_risk: dict[str, int] = Field(default_factory=dict)
    by_segmentation: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class IoTDeviceProfiler:
    """Profile IoT/OT devices and enforce micro-segmentation."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[IoTDeviceRecord] = []
        logger.info(
            "iot_device_profiler.initialized",
            max_records=max_records,
        )

    def add_record(self, **kwargs: Any) -> IoTDeviceRecord:
        record = IoTDeviceRecord(**kwargs)
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "iot_device_profiler.record_added",
            record_id=record.id,
            device_name=record.device_name,
        )
        return record

    def process(self, key: str) -> dict[str, Any]:
        matches = [r for r in self._records if r.id == key]
        if not matches:
            return {"found": False, "key": key}
        rec = matches[0]
        return {
            "found": True,
            "id": rec.id,
            "device_name": rec.device_name,
            "risk_level": rec.risk_level.value,
        }

    # -- domain methods --

    def profile_device(
        self,
        device_name: str,
        device_type: str = "sensor",
        protocol: ProtocolType = ProtocolType.MQTT,
        firmware_version: str = "",
        ip_address: str = "",
    ) -> IoTDeviceRecord:
        """Profile a new IoT/OT device."""
        risk = DeviceRisk.MEDIUM
        if protocol in (ProtocolType.MODBUS, ProtocolType.OPCUA):
            risk = DeviceRisk.HIGH
        record = self.add_record(
            device_name=device_name,
            device_type=device_type,
            protocol=protocol,
            risk_level=risk,
            firmware_version=firmware_version,
            ip_address=ip_address,
        )
        logger.info(
            "iot_device_profiler.device_profiled",
            device_name=device_name,
            risk=risk.value,
        )
        return record

    def detect_protocol_anomaly(
        self,
        device_id: str,
        anomaly_description: str = "",
    ) -> dict[str, Any]:
        """Detect protocol-level anomaly for a device."""
        record = None
        for r in self._records:
            if r.id == device_id:
                record = r
                break
        if record is None:
            return {"found": False, "device_id": device_id}
        record.anomaly_detected = True
        record.risk_level = DeviceRisk.HIGH
        logger.info(
            "iot_device_profiler.anomaly_detected",
            device_id=device_id,
            description=anomaly_description,
        )
        return {
            "found": True,
            "device_id": device_id,
            "device_name": record.device_name,
            "protocol": record.protocol.value,
            "anomaly": anomaly_description,
            "risk_level": record.risk_level.value,
        }

    def enforce_micro_segmentation(
        self,
        device_id: str,
        status: SegmentationStatus = SegmentationStatus.FULLY_SEGMENTED,
    ) -> dict[str, Any]:
        """Enforce micro-segmentation status for a device."""
        record = None
        for r in self._records:
            if r.id == device_id:
                record = r
                break
        if record is None:
            return {"found": False, "device_id": device_id}
        previous = record.segmentation.value
        record.segmentation = status
        logger.info(
            "iot_device_profiler.segmentation_enforced",
            device_id=device_id,
            previous=previous,
            new_status=status.value,
        )
        return {
            "found": True,
            "device_id": device_id,
            "previous_status": previous,
            "new_status": status.value,
        }

    # -- report / stats --

    def generate_report(self) -> IoTDeviceReport:
        by_proto: dict[str, int] = {}
        by_risk: dict[str, int] = {}
        by_seg: dict[str, int] = {}
        for r in self._records:
            by_proto[r.protocol.value] = by_proto.get(r.protocol.value, 0) + 1
            by_risk[r.risk_level.value] = by_risk.get(r.risk_level.value, 0) + 1
            by_seg[r.segmentation.value] = by_seg.get(r.segmentation.value, 0) + 1
        high_risk = sum(
            1 for r in self._records if r.risk_level in (DeviceRisk.CRITICAL, DeviceRisk.HIGH)
        )
        unseg = sum(
            1
            for r in self._records
            if r.segmentation
            in (
                SegmentationStatus.NOT_SEGMENTED,
                SegmentationStatus.UNKNOWN,
            )
        )
        anomalies = sum(1 for r in self._records if r.anomaly_detected)
        recs: list[str] = []
        if high_risk > 0:
            recs.append(f"{high_risk} high-risk device(s)")
        if unseg > 0:
            recs.append(f"{unseg} device(s) need segmentation")
        if anomalies > 0:
            recs.append(f"{anomalies} protocol anomaly(ies) detected")
        if not recs:
            recs.append("IoT/OT fleet healthy")
        return IoTDeviceReport(
            total_devices=len(self._records),
            high_risk_count=high_risk,
            unsegmented_count=unseg,
            anomaly_count=anomalies,
            by_protocol=by_proto,
            by_risk=by_risk,
            by_segmentation=by_seg,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
            "anomalies": sum(1 for r in self._records if r.anomaly_detected),
            "unique_types": len({r.device_type for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("iot_device_profiler.cleared")
        return {"status": "cleared"}
