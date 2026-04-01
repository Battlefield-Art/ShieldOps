"""State models for the Attack Replay Simulator Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ARSStage(StrEnum):
    """Stages of the attack replay simulation lifecycle."""

    SELECT_TECHNIQUES = "select_techniques"
    CONFIGURE_SANDBOX = "configure_sandbox"
    EXECUTE_REPLAY = "execute_replay"
    CAPTURE_TELEMETRY = "capture_telemetry"
    EVALUATE_DETECTION = "evaluate_detection"
    REPORT = "report"


class AttackTechnique(StrEnum):
    """MITRE ATT&CK techniques available for replay."""

    CREDENTIAL_DUMPING = "credential_dumping"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    COMMAND_AND_CONTROL = "command_and_control"
    PERSISTENCE = "persistence"
    DEFENSE_EVASION = "defense_evasion"
    INITIAL_ACCESS = "initial_access"


class DetectionResult(StrEnum):
    """Detection outcome for a replayed technique."""

    DETECTED = "detected"
    PARTIALLY_DETECTED = "partially_detected"
    MISSED = "missed"
    BLOCKED = "blocked"
    DELAYED = "delayed"


class TechniqueSelection(BaseModel):
    """A selected technique for replay."""

    selection_id: str = ""
    technique: AttackTechnique = AttackTechnique.CREDENTIAL_DUMPING
    mitre_id: str = ""
    description: str = ""
    complexity: str = "medium"
    expected_detection: str = ""


class SandboxConfig(BaseModel):
    """Sandbox configuration for attack replay."""

    sandbox_id: str = ""
    environment: str = "isolated"
    os_type: str = "linux"
    network_mode: str = "simulated"
    detection_tools: list[str] = Field(default_factory=list)
    timeout_seconds: int = 300
    capture_pcap: bool = True


class ReplayExecution(BaseModel):
    """Result of a single technique replay execution."""

    execution_id: str = ""
    technique: AttackTechnique = AttackTechnique.CREDENTIAL_DUMPING
    mitre_id: str = ""
    sandbox_id: str = ""
    started_at: datetime | None = None
    completed_at: datetime | None = None
    exit_code: int = 0
    artifacts: list[str] = Field(default_factory=list)
    logs: list[str] = Field(default_factory=list)


class TelemetryCapture(BaseModel):
    """Telemetry captured during attack replay."""

    capture_id: str = ""
    execution_id: str = ""
    alerts_fired: int = 0
    logs_generated: int = 0
    network_events: int = 0
    process_events: int = 0
    file_events: int = 0
    detection_latency_ms: int = 0


class DetectionEvaluation(BaseModel):
    """Evaluation of detection effectiveness."""

    evaluation_id: str = ""
    technique: AttackTechnique = AttackTechnique.CREDENTIAL_DUMPING
    result: DetectionResult = DetectionResult.MISSED
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    detection_latency_ms: int = 0
    alerts_matched: int = 0
    coverage_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class AttackReplaySimulatorState(BaseModel):
    """Full LangGraph state for the Attack Replay Simulator."""

    # Input
    request_id: str = ""
    tenant_id: str = ""
    stage: ARSStage = ARSStage.SELECT_TECHNIQUES
    config: dict[str, Any] = Field(default_factory=dict)

    # Pipeline fields
    techniques: list[dict[str, Any]] = Field(default_factory=list)
    sandbox: dict[str, Any] = Field(default_factory=dict)
    executions: list[dict[str, Any]] = Field(default_factory=list)
    telemetry: list[dict[str, Any]] = Field(default_factory=list)
    evaluations: list[dict[str, Any]] = Field(default_factory=list)
    report: dict[str, Any] = Field(default_factory=dict)

    # Metrics
    technique_count: int = 0
    detected_count: int = 0
    missed_count: int = 0

    # Metadata
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
