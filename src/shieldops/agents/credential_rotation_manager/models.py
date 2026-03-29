"""Credential Rotation Manager Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class RotationStage(StrEnum):
    DISCOVER_CREDENTIALS = "discover_credentials"
    CHECK_AGE = "check_age"
    SCHEDULE_ROTATION = "schedule_rotation"
    EXECUTE_ROTATION = "execute_rotation"
    VALIDATE = "validate"
    REPORT = "report"


class CredentialType(StrEnum):
    API_KEY = "api_key"
    DATABASE_PASSWORD = "database_password"  # noqa: S105
    SSH_KEY = "ssh_key"
    TLS_CERT = "tls_cert"
    TOKEN = "token"  # noqa: S105
    SERVICE_ACCOUNT = "service_account"


class RotationStatus(StrEnum):
    CURRENT = "current"
    DUE = "due"
    OVERDUE = "overdue"
    ROTATING = "rotating"
    FAILED = "failed"
    EXEMPT = "exempt"


class CredentialRotationManagerState(BaseModel):
    request_id: str = ""
    stage: RotationStage = RotationStage.DISCOVER_CREDENTIALS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
