"""Industrial Protocol Analyzer Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class InspectionStage(StrEnum):
    CAPTURE_TRAFFIC = "capture_traffic"
    DECODE_PROTOCOLS = "decode_protocols"
    VALIDATE_COMMANDS = "validate_commands"
    DETECT_ANOMALIES = "detect_anomalies"
    ASSESS_RISK = "assess_risk"
    REPORT = "report"


class IndustrialProtocol(StrEnum):
    MODBUS_TCP = "modbus_tcp"
    MODBUS_RTU = "modbus_rtu"
    DNP3 = "dnp3"
    OPC_UA = "opc_ua"
    BACNET = "bacnet"
    PROFINET = "profinet"


class PacketRisk(StrEnum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"
    REPLAY = "replay"


class ProtocolPacket(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class AnomalyDetection(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class CommandValidation(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class IndustrialProtocolAnalyzerState(BaseModel):
    request_id: str = ""
    stage: InspectionStage = InspectionStage.CAPTURE_TRAFFIC
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
