"""War Gaming Simulator Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SimulationStage(StrEnum):
    DESIGN_SCENARIO = "design_scenario"
    ASSIGN_TEAMS = "assign_teams"
    EXECUTE_ROUNDS = "execute_rounds"
    OBSERVE = "observe"
    SCORE = "score"
    REPORT = "report"


class TeamRole(StrEnum):
    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team"
    WHITE_TEAM = "white_team"
    PURPLE_TEAM = "purple_team"
    OBSERVERS = "observers"


class GameOutcome(StrEnum):
    BLUE_WIN = "blue_win"
    RED_WIN = "red_win"
    DRAW = "draw"
    PARTIAL_CONTAINMENT = "partial_containment"
    ESCALATION = "escalation"


class WarGamingSimulatorState(BaseModel):
    request_id: str = ""
    stage: SimulationStage = SimulationStage.DESIGN_SCENARIO
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
