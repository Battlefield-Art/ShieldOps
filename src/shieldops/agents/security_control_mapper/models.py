"""Security Control Mapper Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class MappingStage(StrEnum):
    COLLECT_CONTROLS = "collect_controls"
    MAP_FRAMEWORKS = "map_frameworks"
    IDENTIFY_GAPS = "identify_gaps"
    CROSS_REFERENCE = "cross_reference"
    SCORE = "score"
    REPORT = "report"


class Framework(StrEnum):
    NIST_CSF = "nist_csf"
    ISO_27001 = "iso_27001"
    CIS_CONTROLS = "cis_controls"
    MITRE_ATTACK = "mitre_attack"
    SOC2 = "soc2"
    PCI_DSS = "pci_dss"


class MappingStatus(StrEnum):
    MAPPED = "mapped"
    PARTIAL = "partial"
    UNMAPPED = "unmapped"
    CONFLICTING = "conflicting"
    DEPRECATED = "deprecated"


class SecurityControlMapperState(BaseModel):
    request_id: str = ""
    stage: MappingStage = MappingStage.COLLECT_CONTROLS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
