"""State models for the File Integrity Monitor Agent."""

from enum import StrEnum

from pydantic import BaseModel, Field


class FIMStage(StrEnum):
    """Stages of the file integrity monitoring workflow."""

    SCAN_BASELINE = "scan_baseline"
    DETECT_CHANGES = "detect_changes"
    CLASSIFY_CHANGES = "classify_changes"
    ASSESS_IMPACT = "assess_impact"
    RESPOND = "respond"
    REPORT = "report"


class ChangeType(StrEnum):
    """Types of file changes detected."""

    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"
    PERMISSIONS_CHANGED = "permissions_changed"
    OWNERSHIP_CHANGED = "ownership_changed"


class ImpactLevel(StrEnum):
    """Impact classification for changed files."""

    CRITICAL_SYSTEM = "critical_system"
    SECURITY_CONFIG = "security_config"
    APPLICATION_CONFIG = "application_config"
    DATA_FILE = "data_file"
    BENIGN = "benign"


class FileBaseline(BaseModel):
    """Baseline snapshot of a monitored file."""

    id: str
    path: str
    sha256_hash: str
    size_bytes: int
    permissions: str
    owner: str
    group: str
    last_modified: float
    monitored_category: str


class FileChange(BaseModel):
    """A detected change to a monitored file."""

    id: str
    baseline_id: str
    path: str
    change_type: ChangeType
    old_hash: str
    new_hash: str
    old_permissions: str = ""
    new_permissions: str = ""
    old_owner: str = ""
    new_owner: str = ""
    detected_at: float
    diff_summary: str = ""


class ChangeClassification(BaseModel):
    """LLM-powered classification of a file change."""

    id: str
    change_id: str
    impact_level: ImpactLevel
    category: str
    explanation: str
    is_authorized: bool
    confidence: float
    related_cve: str = ""


class ImpactAssessment(BaseModel):
    """Impact assessment for a classified file change."""

    id: str
    change_id: str
    affected_services: list[str] = Field(default_factory=list)
    security_impact: str
    compliance_impact: str
    blast_radius: str
    requires_rollback: bool = False


class FIMResponse(BaseModel):
    """Automated response action for a detected change."""

    id: str
    change_id: str
    action: str
    description: str
    executed: bool = False
    success: bool = False
    rollback_available: bool = True


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int
    tool_used: str | None = None


class FileIntegrityMonitorState(BaseModel):
    """Full state of a FIM workflow (LangGraph state)."""

    # Input
    tenant_id: str
    run_id: str = ""
    monitored_paths: list[str] = Field(default_factory=list)

    # Collected data
    baselines: list[FileBaseline] = Field(default_factory=list)
    changes: list[FileChange] = Field(default_factory=list)
    classifications: list[ChangeClassification] = Field(default_factory=list)
    impact_assessments: list[ImpactAssessment] = Field(default_factory=list)
    responses: list[FIMResponse] = Field(default_factory=list)

    # Output
    report_summary: str = ""
    baselines_scanned: int = 0
    changes_detected: int = 0
    critical_changes: int = 0
    compliance_violations: int = 0

    # Metadata
    stage: FIMStage = FIMStage.SCAN_BASELINE
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    started_at: float = 0.0
    duration_ms: int = 0
    error: str | None = None
