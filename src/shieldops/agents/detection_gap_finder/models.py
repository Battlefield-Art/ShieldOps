"""Detection Gap Finder Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class GapFinderStage(StrEnum):
    """Stages of the detection gap finder pipeline."""

    SELECT_TECHNIQUES = "select_techniques"
    SIMULATE_ATTACKS = "simulate_attacks"
    MONITOR_DETECTIONS = "monitor_detections"
    IDENTIFY_BLIND_SPOTS = "identify_blind_spots"
    PRIORITIZE_GAPS = "prioritize_gaps"
    REPORT = "report"


class SimulationType(StrEnum):
    """Types of safe attack simulation."""

    ATOMIC_TEST = "atomic_test"
    LOG_REPLAY = "log_replay"
    BEHAVIOR_SIMULATION = "behavior_simulation"
    IOC_INJECTION = "ioc_injection"
    TRAFFIC_REPLAY = "traffic_replay"


class DetectionOutcome(StrEnum):
    """Outcome of detection monitoring after simulation."""

    DETECTED = "detected"
    PARTIALLY_DETECTED = "partially_detected"
    MISSED = "missed"
    FALSE_NEGATIVE = "false_negative"


class TechniqueSelection(BaseModel):
    """A MITRE technique selected for simulation."""

    technique_id: str = ""
    technique_name: str = ""
    tactic: str = ""
    simulation_type: SimulationType = SimulationType.LOG_REPLAY
    risk_priority: float = 0.0


class AttackSimulation(BaseModel):
    """Result of a safe attack simulation."""

    id: str = ""
    technique_id: str = ""
    simulation_type: SimulationType = SimulationType.LOG_REPLAY
    artifacts_generated: list[str] = Field(
        default_factory=list,
    )
    logs_injected: int = 0
    timestamp: float = 0.0
    safe: bool = True


class DetectionMonitor(BaseModel):
    """Monitoring result for whether a detection fired."""

    simulation_id: str = ""
    technique_id: str = ""
    outcome: DetectionOutcome = DetectionOutcome.MISSED
    alert_id: str = ""
    detection_time_sec: float = 0.0
    rule_name: str = ""


class BlindSpot(BaseModel):
    """An identified detection blind spot."""

    technique_id: str = ""
    technique_name: str = ""
    tactic: str = ""
    outcome: DetectionOutcome = DetectionOutcome.MISSED
    data_sources_available: list[str] = Field(
        default_factory=list,
    )
    root_cause: str = ""


class GapPrioritization(BaseModel):
    """A prioritized detection gap."""

    technique_id: str = ""
    technique_name: str = ""
    risk_score: float = 0.0
    exploitability: str = ""
    business_impact: str = ""
    remediation_effort: str = ""
    priority_rank: int = 0


class DetectionGapFinderState(BaseModel):
    """Full state for a detection gap finder run."""

    # Input
    tenant_id: str = ""
    request_id: str = ""

    # Pipeline data
    techniques_selected: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    simulations_run: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    detections_monitored: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    blind_spots: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    prioritized_gaps: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Metrics
    detection_rate: float = 0.0
    missed_techniques: int = 0

    # Workflow tracking
    current_stage: str = GapFinderStage.SELECT_TECHNIQUES
    reasoning_chain: list[str] = Field(
        default_factory=list,
    )
    error: str = ""
