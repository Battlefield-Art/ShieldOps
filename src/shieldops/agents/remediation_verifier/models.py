"""State models for the Remediation Verifier Agent."""

from __future__ import annotations

from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class VerifierStage(StrEnum):
    """Stages of the remediation verification workflow."""

    COLLECT_REMEDIATIONS = "collect_remediations"
    DESIGN_VERIFICATION_TESTS = "design_verification_tests"
    EXECUTE_TESTS = "execute_tests"
    ASSESS_RESULTS = "assess_results"
    FLAG_REGRESSIONS = "flag_regressions"
    REPORT = "report"


class TestType(StrEnum):
    """Types of verification tests."""

    RESCAN = "rescan"
    EXPLOIT_RETEST = "exploit_retest"
    CONFIG_CHECK = "config_check"
    ACCESS_CHECK = "access_check"
    POLICY_CHECK = "policy_check"


class VerificationResult(StrEnum):
    """Result of a verification test."""

    FIXED = "fixed"
    PARTIALLY_FIXED = "partially_fixed"
    NOT_FIXED = "not_fixed"
    REGRESSION = "regression"
    NEW_ISSUE = "new_issue"


class RemediationRecord(BaseModel):
    """Record of a completed remediation."""

    id: str = Field(default_factory=lambda: f"rem-{uuid4().hex[:12]}")
    finding_id: str
    finding_title: str = ""
    remediation_type: str = ""
    asset: str = ""
    applied_at: float = 0.0
    applied_by: str = ""
    original_severity: str = "high"


class VerificationTest(BaseModel):
    """A verification test to run."""

    id: str = Field(default_factory=lambda: f"vt-{uuid4().hex[:12]}")
    remediation_id: str
    test_type: TestType
    description: str = ""
    target: str = ""
    expected_outcome: str = "fixed"


class TestExecution(BaseModel):
    """Execution record of a verification test."""

    id: str = Field(default_factory=lambda: f"te-{uuid4().hex[:12]}")
    test_id: str
    remediation_id: str
    result: VerificationResult = VerificationResult.FIXED
    actual_output: str = ""
    expected_output: str = ""
    executed_at: float = 0.0
    duration_sec: float = 0.0


class ResultAssessment(BaseModel):
    """Assessment of verification test results."""

    id: str = Field(default_factory=lambda: f"ra-{uuid4().hex[:12]}")
    remediation_id: str
    overall_result: VerificationResult
    confidence: float = 0.0
    details: str = ""
    needs_attention: bool = False


class RegressionFlag(BaseModel):
    """A flagged regression or new issue."""

    id: str = Field(default_factory=lambda: f"rf-{uuid4().hex[:12]}")
    remediation_id: str
    regression_type: str = ""
    description: str = ""
    severity: str = "medium"
    asset: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int
    tool_used: str | None = None


class RemediationVerifierState(BaseModel):
    """Full state of the remediation verifier workflow."""

    # Input
    tenant_id: str = ""
    request_id: str = Field(default_factory=lambda: f"req-{uuid4().hex[:12]}")

    # Pipeline
    remediations_collected: list[RemediationRecord] = Field(default_factory=list)
    tests_designed: list[VerificationTest] = Field(default_factory=list)
    tests_executed: list[TestExecution] = Field(default_factory=list)
    results_assessed: list[ResultAssessment] = Field(default_factory=list)
    regressions_found: list[RegressionFlag] = Field(default_factory=list)

    # Counters
    verified_fixed_count: int = 0
    still_vulnerable_count: int = 0

    # Report
    report_summary: str = ""

    # Metadata
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_stage: str = "init"
    error: str = ""
    duration_ms: int = 0
