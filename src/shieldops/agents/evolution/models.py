"""State models for the Evolution Engine Agent LangGraph workflow."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class EvolutionStage(StrEnum):
    """Stages of the evolution pipeline."""

    MEASURE_FITNESS = "measure_fitness"
    ANALYZE_PATTERNS = "analyze_patterns"
    EVOLVE_PROMPTS = "evolve_prompts"
    PROPAGATE_LEARNINGS = "propagate_learnings"
    DEPLOY_CHANGES = "deploy_changes"
    VALIDATE_EVOLUTION = "validate_evolution"
    REPORT = "report"


class EvolutionStrategy(StrEnum):
    """Strategy for evolving an agent."""

    PROMPT_REFINE = "prompt_refine"
    THRESHOLD_TUNE = "threshold_tune"
    WORKFLOW_ADJUST = "workflow_adjust"
    CONTEXT_ENRICH = "context_enrich"
    CROSS_POLLINATE = "cross_pollinate"


class DeploymentStatus(StrEnum):
    """Status of an evolution deployment."""

    PENDING = "pending"
    TESTING = "testing"
    DEPLOYED = "deployed"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


# --- Domain Models ---


class AgentGenome(BaseModel):
    """Evolvable configuration for an agent — its 'DNA'.

    Captures everything that can be tuned without code changes:
    prompts, thresholds, routing weights, feature flags.
    """

    agent_id: str = ""
    agent_type: str = ""
    generation: int = 0
    prompt_versions: dict[str, str] = Field(
        default_factory=dict,
        description="node_name → active prompt version_id",
    )
    thresholds: dict[str, float] = Field(
        default_factory=dict,
        description="Tunable thresholds: confidence, severity, etc.",
    )
    routing_weights: dict[str, float] = Field(
        default_factory=dict,
        description="Weights for conditional routing decisions",
    )
    feature_flags: dict[str, bool] = Field(
        default_factory=dict,
        description="Feature toggles for agent behavior",
    )
    fitness_score: float = 0.0
    parent_genome_id: str = ""
    created_at: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvolutionCandidate(BaseModel):
    """An agent identified as a candidate for evolution."""

    agent_id: str = ""
    agent_type: str = ""
    fitness_score: float = 0.0
    weakest_dimension: str = ""
    strongest_dimension: str = ""
    trend: str = ""
    suggested_strategy: EvolutionStrategy = EvolutionStrategy.PROMPT_REFINE
    improvement_opportunity: str = ""
    priority: int = 3


class PromptMutation(BaseModel):
    """A proposed prompt mutation for an agent node."""

    agent_id: str = ""
    node_name: str = ""
    current_prompt: str = ""
    proposed_prompt: str = ""
    mutation_type: str = ""
    reason: str = ""
    expected_improvement: float = 0.0
    risk_score: float = 0.0


class LearningPropagation(BaseModel):
    """Record of a learning being propagated across agents."""

    source_agent_id: str = ""
    target_agent_ids: list[str] = Field(default_factory=list)
    learning_type: str = ""
    description: str = ""
    applied_count: int = 0
    rejected_count: int = 0


class EvolutionDeployment(BaseModel):
    """A deployment of evolved agent configuration."""

    deployment_id: str = ""
    agent_id: str = ""
    strategy: EvolutionStrategy = EvolutionStrategy.PROMPT_REFINE
    changes: dict[str, Any] = Field(default_factory=dict)
    status: DeploymentStatus = DeploymentStatus.PENDING
    rollback_info: dict[str, Any] = Field(default_factory=dict)
    validation_score: float = 0.0


class ValidationResult(BaseModel):
    """Result of validating an evolution deployment."""

    deployment_id: str = ""
    agent_id: str = ""
    pre_evolution_fitness: float = 0.0
    post_evolution_fitness: float = 0.0
    improvement_pct: float = 0.0
    regression_detected: bool = False
    dimensions_improved: list[str] = Field(default_factory=list)
    dimensions_degraded: list[str] = Field(default_factory=list)
    verdict: str = ""


# --- Agent State ---


class EvolutionState(BaseModel):
    """Full state for an evolution engine workflow run."""

    # Input
    request_id: str = ""
    tenant_id: str = ""
    target_agent_ids: list[str] = Field(
        default_factory=list,
        description="Specific agents to evolve. Empty = auto-select candidates.",
    )
    max_candidates: int = 10
    dry_run: bool = False

    # Pipeline data
    stage: EvolutionStage = EvolutionStage.MEASURE_FITNESS
    candidates: list[EvolutionCandidate] = Field(default_factory=list)
    genomes: list[AgentGenome] = Field(default_factory=list)
    mutations: list[PromptMutation] = Field(default_factory=list)
    propagations: list[LearningPropagation] = Field(default_factory=list)
    deployments: list[EvolutionDeployment] = Field(default_factory=list)
    validations: list[ValidationResult] = Field(default_factory=list)

    # Metrics
    total_agents_evaluated: int = 0
    total_candidates: int = 0
    total_mutations: int = 0
    total_deployments: int = 0
    total_learnings_propagated: int = 0
    fleet_fitness_before: float = 0.0
    fleet_fitness_after: float = 0.0
    improvement_pct: float = 0.0

    # Workflow tracking
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
