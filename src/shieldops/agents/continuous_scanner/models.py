"""State models for the Continuous Scanner Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SchedulerStage(StrEnum):
    """Stages of the continuous scanner workflow."""

    LOAD_SCHEDULE = "load_schedule"
    CHECK_DUE_SCANS = "check_due_scans"
    DISPATCH_SCANS = "dispatch_scans"
    MONITOR_PROGRESS = "monitor_progress"
    COLLECT_RESULTS = "collect_results"
    REPORT = "report"


class ScanFrequency(StrEnum):
    """How often a scan should run."""

    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    ON_CHANGE = "on_change"


class ScanType(StrEnum):
    """Types of security scans."""

    NETWORK = "network"
    WEB_APP = "web_app"
    CLOUD = "cloud"
    API = "api"
    CREDENTIAL = "credential"
    COMPLIANCE = "compliance"


class ScanSchedule(BaseModel):
    """A configured scan schedule entry."""

    id: str = ""
    name: str = ""
    scan_type: ScanType = ScanType.NETWORK
    frequency: ScanFrequency = ScanFrequency.DAILY
    target_assets: list[str] = Field(default_factory=list)
    agent_name: str = ""
    last_run_at: str = ""
    next_run_at: str = ""
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)


class DueScan(BaseModel):
    """A scan that is due for execution."""

    schedule_id: str = ""
    scan_type: ScanType = ScanType.NETWORK
    agent_name: str = ""
    target_assets: list[str] = Field(default_factory=list)
    overdue_minutes: int = 0
    priority: int = 0


class ScanDispatch(BaseModel):
    """Record of a dispatched scan."""

    schedule_id: str = ""
    agent_name: str = ""
    dispatch_id: str = ""
    status: str = "dispatched"
    dispatched_at: str = ""


class ScanProgress(BaseModel):
    """Progress of a running scan."""

    dispatch_id: str = ""
    agent_name: str = ""
    status: str = ""
    progress_pct: float = 0.0
    findings_so_far: int = 0
    elapsed_ms: int = 0


class ScanResult(BaseModel):
    """Final result from a completed scan."""

    dispatch_id: str = ""
    schedule_id: str = ""
    agent_name: str = ""
    status: str = ""
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    duration_ms: int = 0
    details: dict[str, Any] = Field(default_factory=dict)


class ContinuousScannerState(BaseModel):
    """Full state for the continuous scanner workflow."""

    # Input
    tenant_id: str = ""
    request_id: str = ""

    # Pipeline data
    schedules: list[ScanSchedule] = Field(default_factory=list)
    due_scans: list[DueScan] = Field(default_factory=list)
    dispatched: list[ScanDispatch] = Field(default_factory=list)
    in_progress: list[ScanProgress] = Field(default_factory=list)
    completed: list[ScanResult] = Field(default_factory=list)

    # Metrics
    scans_run_today: int = 0
    coverage_pct: float = 0.0
    next_scan_due: str = ""

    # Workflow tracking
    current_stage: SchedulerStage = SchedulerStage.LOAD_SCHEDULE
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
    session_duration_ms: int = 0
