"""State models for the Data Threat Hunting Agent."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class HuntStage(StrEnum):
    """Stages of a data threat hunting campaign."""

    init = "init"
    generate_hypotheses = "generate_hypotheses"
    collect_evidence = "collect_evidence"
    analyze_indicators = "analyze_indicators"
    hunt_in_backups = "hunt_in_backups"
    correlate_findings = "correlate_findings"
    report = "report"
    complete = "complete"
    failed = "failed"


class HuntSource(StrEnum):
    """Data sources available for threat hunting."""

    production = "production"
    backup_snapshot = "backup_snapshot"
    ai_pipeline = "ai_pipeline"
    cloud_storage = "cloud_storage"
    database = "database"


class ThreatVerdict(StrEnum):
    """Verdict classifications for hunt findings."""

    confirmed_threat = "confirmed_threat"
    likely_threat = "likely_threat"
    suspicious = "suspicious"
    benign = "benign"
    inconclusive = "inconclusive"


class HuntHypothesis(BaseModel):
    """A threat hunting hypothesis generated from intel."""

    hypothesis_id: str = ""
    description: str = ""
    mitre_techniques: list[str] = Field(
        default_factory=list,
    )
    target_sources: list[str] = Field(
        default_factory=list,
    )
    confidence: float = 0.0
    rationale: str = ""
    priority: str = "medium"


class EvidenceCollection(BaseModel):
    """Evidence collected from a specific data source."""

    source: str = ""
    source_type: str = ""
    artifacts: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    query_used: str = ""
    time_range: str = ""
    record_count: int = 0
    collection_timestamp: datetime | None = None


class IndicatorAnalysis(BaseModel):
    """Analysis result for a set of indicators."""

    indicator_type: str = ""
    indicator_value: str = ""
    matched: bool = False
    match_source: str = ""
    severity: str = "low"
    context: dict[str, Any] = Field(
        default_factory=dict,
    )
    behavioral_pattern: str = ""


class BackupScanResult(BaseModel):
    """Result from scanning a backup snapshot."""

    snapshot_id: str = ""
    snapshot_date: str = ""
    source_system: str = ""
    threats_found: int = 0
    anomalies_found: int = 0
    ransomware_staging: bool = False
    persistence_detected: bool = False
    exfiltration_traces: bool = False
    details: list[dict[str, Any]] = Field(
        default_factory=list,
    )


class HuntFinding(BaseModel):
    """A consolidated finding from the hunt campaign."""

    finding_id: str = ""
    verdict: str = ThreatVerdict.inconclusive
    severity: str = "low"
    confidence: float = 0.0
    sources: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(
        default_factory=list,
    )
    description: str = ""
    evidence_refs: list[str] = Field(
        default_factory=list,
    )
    recommended_actions: list[str] = Field(
        default_factory=list,
    )
    cross_source_correlated: bool = False


class ReasoningStep(BaseModel):
    """Audit trail entry for the hunt workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class DataThreatHuntingState(BaseModel):
    """Full state for a data threat hunting workflow run."""

    # Input
    tenant_id: str = ""
    hunt_id: str = ""
    initial_hypotheses: list[str] = Field(
        default_factory=list,
    )
    target_sources: list[str] = Field(
        default_factory=list,
    )
    hunt_scope: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Hypothesis generation
    hypotheses: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Evidence collection
    evidence: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Indicator analysis
    indicators: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Backup scanning
    backup_scans: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Findings and correlation
    findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    threats_confirmed: int = 0

    # Timing
    hunt_duration_seconds: float = 0.0
    session_start: datetime | None = None

    # Report
    hunt_report: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Workflow tracking
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = HuntStage.init
    error: str | None = None
