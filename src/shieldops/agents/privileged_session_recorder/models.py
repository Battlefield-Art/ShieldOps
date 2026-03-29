"""Privileged Session Recorder Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class RecordingStage(StrEnum):
    DETECT_SESSION = "detect_session"
    START_RECORDING = "start_recording"
    MONITOR_COMMANDS = "monitor_commands"
    DETECT_ANOMALIES = "detect_anomalies"
    ARCHIVE = "archive"
    REPORT = "report"


class SessionType(StrEnum):
    SSH = "ssh"
    RDP = "rdp"
    DATABASE = "database"
    CLOUD_CONSOLE = "cloud_console"
    API = "api"
    LOCAL_ADMIN = "local_admin"


class AnomalyType(StrEnum):
    UNUSUAL_COMMAND = "unusual_command"
    DATA_EXFIL = "data_exfil"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    POLICY_VIOLATION = "policy_violation"
    OFF_HOURS = "off_hours"
    UNKNOWN_SOURCE = "unknown_source"


class PrivilegedSessionRecorderState(BaseModel):
    request_id: str = ""
    stage: RecordingStage = RecordingStage.DETECT_SESSION
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
