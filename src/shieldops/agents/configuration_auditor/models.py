"""Configuration Auditor Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CAStage(StrEnum):
    COLLECT_CONFIGS = "collect_configs"
    PARSE_SETTINGS = "parse_settings"
    VALIDATE_SECURITY = "validate_security"
    DETECT_DRIFT = "detect_drift"
    RECOMMEND_FIXES = "recommend_fixes"
    REPORT = "report"


class ConfigSource(StrEnum):
    KUBERNETES = "kubernetes"
    TERRAFORM = "terraform"
    ANSIBLE = "ansible"
    DOCKER = "docker"
    CLOUD_NATIVE = "cloud_native"
    APPLICATION = "application"


class DriftSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    COMPLIANT = "compliant"


class ConfigurationAuditorState(BaseModel):
    request_id: str = ""
    stage: CAStage = CAStage.COLLECT_CONFIGS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
