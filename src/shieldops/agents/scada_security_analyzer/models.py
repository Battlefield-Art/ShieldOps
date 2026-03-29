"""SCADA Security Analyzer Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AnalysisStage(StrEnum):
    DISCOVER_ASSETS = "discover_assets"
    ANALYZE_TRAFFIC = "analyze_traffic"
    DETECT_ANOMALIES = "detect_anomalies"
    CHECK_FIRMWARE = "check_firmware"
    ASSESS_RISK = "assess_risk"
    REPORT = "report"


class ProtocolType(StrEnum):
    MODBUS = "modbus"
    DNP3 = "dnp3"
    OPC_UA = "opc_ua"
    BACNET = "bacnet"
    PROFINET = "profinet"
    ETHERCAT = "ethercat"


class ThreatLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class SCADAEvent(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class SecurityFinding(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class FirmwareCheck(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class SCADASecurityAnalyzerState(BaseModel):
    request_id: str = ""
    stage: AnalysisStage = AnalysisStage.DISCOVER_ASSETS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
