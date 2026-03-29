"""Artifact Integrity Checker Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CheckStage(StrEnum):
    COLLECT_ARTIFACTS = "collect_artifacts"
    VERIFY_SIGNATURES = "verify_signatures"
    CHECK_CHECKSUMS = "check_checksums"
    VALIDATE_PROVENANCE = "validate_provenance"
    ASSESS = "assess"
    REPORT = "report"


class ArtifactType(StrEnum):
    CONTAINER_IMAGE = "container_image"
    BINARY = "binary"
    PACKAGE = "package"
    LIBRARY = "library"
    FIRMWARE = "firmware"
    CONFIG = "config"


class IntegrityStatus(StrEnum):
    VERIFIED = "verified"
    TAMPERED = "tampered"
    UNSIGNED = "unsigned"
    EXPIRED_SIG = "expired_sig"
    UNKNOWN = "unknown"


class ArtifactIntegrityCheckerState(BaseModel):
    request_id: str = ""
    stage: CheckStage = CheckStage.COLLECT_ARTIFACTS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
