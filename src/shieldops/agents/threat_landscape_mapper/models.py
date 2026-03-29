"""Threat Landscape Mapper Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class MappingStage(StrEnum):
    COLLECT_INTEL = "collect_intel"
    MAP_ACTORS = "map_actors"
    IDENTIFY_TRENDS = "identify_trends"
    ASSESS_RELEVANCE = "assess_relevance"
    PRIORITIZE = "prioritize"
    REPORT = "report"


class ThreatCategory(StrEnum):
    RANSOMWARE = "ransomware"
    APT = "apt"
    SUPPLY_CHAIN = "supply_chain"
    INSIDER = "insider"
    HACKTIVISM = "hacktivism"
    CYBER_CRIME = "cyber_crime"


class RelevanceLevel(StrEnum):
    DIRECT_THREAT = "direct_threat"
    ADJACENT = "adjacent"
    PERIPHERAL = "peripheral"
    THEORETICAL = "theoretical"
    NEGLIGIBLE = "negligible"


class ThreatLandscapeMapperState(BaseModel):
    request_id: str = ""
    stage: MappingStage = MappingStage.COLLECT_INTEL
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
