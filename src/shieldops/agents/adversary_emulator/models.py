"""Adversary Emulator Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class EmulationStage(StrEnum):
    SELECT_ADVERSARY = "select_adversary"
    PLAN_CAMPAIGN = "plan_campaign"
    EXECUTE_TTPS = "execute_ttps"
    OBSERVE_DEFENSES = "observe_defenses"
    SCORE = "score"
    REPORT = "report"


class AdversaryGroup(StrEnum):
    APT29 = "apt29"
    APT28 = "apt28"
    LAZARUS = "lazarus"
    FIN7 = "fin7"
    CONTI = "conti"
    CUSTOM = "custom"


class EmulationResult(StrEnum):
    DETECTED = "detected"
    PARTIALLY_DETECTED = "partially_detected"
    MISSED = "missed"
    BLOCKED = "blocked"
    ALERTED = "alerted"


class AdversaryEmulatorState(BaseModel):
    request_id: str = ""
    stage: EmulationStage = EmulationStage.SELECT_ADVERSARY
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
