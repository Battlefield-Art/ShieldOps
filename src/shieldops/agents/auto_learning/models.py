"""Auto Learning Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class LearningStage(StrEnum):
    ASSESS = "assess"
    PROPOSE = "propose"
    EXPERIMENT = "experiment"
    EVALUATE = "evaluate"
    DECIDE = "decide"


class ExperimentType(StrEnum):
    THRESHOLD_TUNING = "threshold_tuning"
    ALERT_RULE_UPDATE = "alert_rule_update"
    RUNBOOK_REFINEMENT = "runbook_refinement"
    ROUTING_OPTIMIZATION = "routing_optimization"
    POLICY_ADJUSTMENT = "policy_adjustment"


class ExperimentOutcome(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    TIMED_OUT = "timed_out"


class ResourceBudget(BaseModel):
    """Fixed resource budget for an experiment (autoresearch pattern)."""

    max_duration_seconds: int = 300  # 5-minute cap like autoresearch
    max_api_calls: int = 50
    max_memory_mb: int = 256
    max_concurrent: int = 1


class BaselineMetrics(BaseModel):
    """Current performance baseline to improve against."""

    mttr_seconds: float = 0.0
    false_positive_rate: float = 0.0
    alert_noise_ratio: float = 0.0
    resolution_accuracy: float = 0.0
    agent_confidence_avg: float = 0.0
    custom_metric: str = ""
    custom_value: float = 0.0


class Proposal(BaseModel):
    """A proposed change to evaluate."""

    id: str = ""
    experiment_type: ExperimentType = ExperimentType.THRESHOLD_TUNING
    description: str = ""
    target_module: str = ""
    parameter_changes: dict[str, Any] = Field(default_factory=dict)
    expected_improvement: float = 0.0
    risk_score: float = 0.0


class ExperimentResult(BaseModel):
    """Result of running a proposed change."""

    proposal_id: str = ""
    outcome: ExperimentOutcome = ExperimentOutcome.INCONCLUSIVE
    baseline_metric_value: float = 0.0
    experiment_metric_value: float = 0.0
    improvement_pct: float = 0.0
    duration_seconds: float = 0.0
    api_calls_used: int = 0
    within_budget: bool = True
    rollback_needed: bool = False


class AutoLearningState(BaseModel):
    """Main state for the Auto Learning agent graph."""

    request_id: str = ""
    stage: LearningStage = LearningStage.ASSESS
    iteration: int = 0
    max_iterations: int = 10

    # Budget
    budget: ResourceBudget = Field(default_factory=ResourceBudget)

    # Assessment
    baseline: BaselineMetrics = Field(default_factory=BaselineMetrics)
    improvement_areas: list[str] = Field(default_factory=list)

    # Proposals
    proposals: list[Proposal] = Field(default_factory=list)
    current_proposal: Proposal | None = None

    # Results
    experiment_results: list[ExperimentResult] = Field(default_factory=list)
    accepted_changes: list[dict[str, Any]] = Field(default_factory=list)
    rejected_changes: list[dict[str, Any]] = Field(default_factory=list)

    # Output
    total_experiments: int = 0
    acceptance_rate: float = 0.0
    cumulative_improvement: float = 0.0
    recommendations: list[str] = Field(default_factory=list)
    confidence_score: float = 0.0
    reasoning_chain: list[str] = Field(default_factory=list)
